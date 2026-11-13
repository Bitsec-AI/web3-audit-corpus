"""Extract a ground-truth record for each finding in the starter audits, for the review app in review/.

Per finding: files, contracts, functions, function-to-contract pairs, root-cause class (corpus label),
a root-cause sentence, an impact sentence, and other findings in the same audit that name the same function.
Everything is read from the finding text with regexes; each extracted sentence records which section it came from.

    .venv/bin/python -I benchmark-review/review_data.py --release data/release --scope data/release/scope
"""
import argparse
import json
import re
import sys
from pathlib import Path

import duckdb

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import readiness as R  # noqa: E402
from shortlist import ISSUE_LINK  # noqa: E402

SECTION_NAMES = {
    "summary": "summary", "root cause": "root_cause", "vulnerability detail": "detail", "vulnerability details": "detail",
    "detailed description": "detail", "description": "detail", "brief description": "detail", "bug description": "detail",
    "impact": "impact", "attack path": "attack", "internal pre-conditions": "pre", "external pre-conditions": "pre",
    "proof of concept": "poc", "poc": "poc", "coded poc": "poc", "code snippet": "snippet", "lines of code": "loc",
    "tool used": "tools", "tools used": "tools", "recommendation": "fix", "recommendations": "fix", "mitigation": "fix",
    "recommended mitigation": "fix", "recommended mitigation steps": "fix", "suggested mitigation": "fix",
    "discussion": "discussion", "found by": "found_by", "assessed type": "assessed",
}
HEADING = re.compile(r"^\s*(?:#{1,6}\s*)?\**\s*(" + "|".join(sorted(map(re.escape, SECTION_NAMES), key=len, reverse=True)) +
                     r")\s*\**\s*:?\s*\**\s*$", re.I | re.M)
BLOB_LINK = re.compile(r"github\.com/([\w.-]+/[\w.-]+)/blob/[\w.-]+/([^\s#)>\]?]+)")
SOURCE_MENTION = re.compile(r"(?<![\w/.-])([\w/.-]*?([A-Za-z_]\w*)\.(?:sol|vy|rs|move|cairo))\b")
SOURCE_EXT = re.compile(r"\.(?:sol|vy|rs|move|cairo)$")
FILE_LABEL = re.compile(r"^\s*File:\s*([\w/.-]+\.(?:sol|vy|rs|move|cairo))", re.M)
QUALIFIED = re.compile(r"\b([A-Z][A-Za-z0-9_]*)(?:\.|::)(_?[a-z]\w*)")
NOT_CONTRACTS = {"SafeERC20", "SafeTransferLib", "Math", "FixedPointMathLib", "SafeCast", "Address", "ECDSA", "ERC20", "ERC721",
                 "Strings", "EnumerableSet", "Clones", "MerkleProof", "console", "Errors", "Events", "Solmate", "OpenZeppelin"}
QA_LEAK = re.compile(r"low risk and non-critical issues|non-critical issues list|low risk issues list", re.I)
FENCE = re.compile(r"```.*?(?:```|\Z)", re.S)
MD_LINK = re.compile(r"!?\[([^\]]*)\]\([^)]*\)")
URL = re.compile(r"<?https?://\S+>?")
SENTENCE_END = re.compile(r"(?<=[.!?])\s+(?=[A-Z`(\[])")


def sections(body):
    """First non-empty text under each known heading, keyed by section kind; the text before the first heading is 'lead'."""
    out = {}
    marks = list(HEADING.finditer(body))
    out["lead"] = body[:marks[0].start()] if marks else body
    for m, nxt in zip(marks, marks[1:] + [None]):
        kind = SECTION_NAMES[m.group(1).lower()]
        text = body[m.end():nxt.start() if nxt else len(body)]
        if kind not in out and prose(text):
            out[kind] = text
    return out


def prose(text, limit=500):
    """The first readable paragraph of a section, without code, links or headers, cut to about two sentences."""
    text = MD_LINK.sub(r"\1", FENCE.sub("\n\n", text))
    for para in re.split(r"\n\s*\n", text):
        lines = [l.strip() for l in para.splitlines()]
        lines = [l for l in lines if l and not l.lstrip("*_ ").startswith(("#", "|", "Submitted by", "Source:", "Issue ", "File:"))
                 and not re.match(r"^\d+:\s", l) and not re.fullmatch(r"<?https?://\S+>?(<br>)?", l)]
        joined = re.sub(r"\s+", " ", " ".join(lines)).replace(",! ", "").strip()
        joined = URL.sub("", joined).strip()
        if len(re.findall(r"[A-Za-z]", joined)) >= 30:
            sentences = SENTENCE_END.split(joined)
            out = " ".join(sentences[:2])
            return out if len(out) <= limit else out[:limit].rsplit(" ", 1)[0] + "…"
    return None


def first_prose(secs, order):
    for kind in order:
        if kind in secs and (text := prose(secs[kind])):
            return text, kind
    return None, None


def is_test(path):
    return "/test" in f"/{path}" or path.endswith(".t.sol") or Path(path).name.lower().startswith("test")


def files_in(text, contest_repo, scope_names):
    """Source files the finding points at: GitHub blob links, 'File:' labels in code and file names in prose."""
    found = {}
    for repo, path in BLOB_LINK.findall(text):
        path = path.rstrip(".,;:").replace("\\_", "_")
        if is_test(path) or not SOURCE_EXT.search(path):
            continue
        # Contest copies of the code live under sherlock-audit/ or code-423n4/; other repos are libraries unless the file is in scope.
        external = repo.split("/")[0].lower() not in ("sherlock-audit", "code-423n4") and repo.lower() != contest_repo.lower() \
            and Path(path).name not in scope_names
        found.setdefault(Path(path).name, {"path": path, "how": "link", "external": external})
    for path in FILE_LABEL.findall(text) + [m[0] for m in SOURCE_MENTION.findall(FENCE.sub(" ", text))]:
        name = Path(path).name
        if is_test(path):
            continue
        found.setdefault(name, {"path": path, "how": "mention", "external": False})
    for name, rec in found.items():
        rec["name"] = name
        rec["in_scope"] = name in scope_names if scope_names else None
    return list(found.values())


def contracts_in(text, files, functions):
    """Contract names from in-repo file names and Contract.function / Contract::function references; returns (contracts, pairs)."""
    names = [Path(f["name"]).stem for f in files if not f["external"] and f["name"].endswith(".sol")]
    pairs = {}
    for contract, fn in QUALIFIED.findall(R.CODE_BLOCK.sub(" ", text)):
        if contract in NOT_CONTRACTS or re.match(r"^I[A-Z]", contract) or fn not in functions:
            continue
        pairs.setdefault(fn, contract)
        if contract not in names:
            names.append(contract)
    names = [n for n in names if n not in NOT_CONTRACTS]
    if len(names) == 1:
        for fn in functions:
            pairs.setdefault(fn, names[0])
    return names, [{"function": fn, "contract": pairs.get(fn)} for fn in functions]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    ap.add_argument("--scope", default="data/release/scope")
    ap.add_argument("--out", default=str(HERE / "review" / "findings.json"))
    args = ap.parse_args()
    ids = [l.strip() for l in (HERE / "shortlist_56.txt").read_text().splitlines() if l.startswith("engagement:")]

    c = duckdb.connect()
    c.execute(f"create view e as select * from read_csv_auto('{args.release}/engagements.csv', all_varchar=true)")
    c.execute(f"create view r as select * from read_csv_auto('{args.release}/reports.csv', all_varchar=true)")
    df = c.execute(
        f"""select f.finding_uid, f.engagement_id, f.firm_id platform, f.finding_id, f.title, f.severity, f.vuln_group, f.vuln_leaf,
                   f.vuln_confidence, f.vuln_needs_review, f.body_text, f.ordinal, e.project, try_cast(e.audit_year as int) audit_year, r.url report_url
            from '{args.release}/findings.parquet' f join e using(engagement_id) left join r on r.report_id = e.primary_report_id
            where f.selected_for_stats and f.severity in ('critical','high','medium') and f.body_text_status = 'present'
              and f.engagement_id in (select unnest(?))
            order by e.project, f.ordinal""", [ids]).df()
    scope = R.load_scope(args.scope)
    df = R.apply_contest_names(df.merge(scope[["engagement_id", "contest_title", "contest_year"]], on="engagement_id", how="left"))
    df = df.merge(scope[["engagement_id", "contest_key", "nsloc", "repo", "commit"]], on="engagement_id", how="left")
    scope_files = {}
    for path in Path(args.scope).glob("*.json"):
        rec = json.loads(path.read_text())
        if "engagement_id" in rec and rec["engagement_id"] in ids:
            scope_files[rec["engagement_id"]] = {Path(f["name"]).name for f in rec.get("files") or []}

    records = []
    for row in df.itertuples():
        body = row.body_text
        desc = R.description(body)
        secs = sections(body)
        functions = R.functions_in(body)
        files = files_in(desc + "\n" + secs.get("snippet", "") + "\n" + secs.get("loc", ""), row.repo or "", scope_files.get(row.engagement_id) or set())
        contracts, fn_contract = contracts_in(desc, files, functions)
        root, root_from = first_prose(secs, ["root_cause", "summary", "detail", "lead", "poc", "attack"])
        impact, impact_from = first_prose(secs, ["impact"])
        if not root:
            root, root_from = row.title, "title"
        records.append({
            "uid": row.finding_uid, "engagement_id": row.engagement_id, "project": row.project, "platform": row.platform,
            "audit_year": None if row.audit_year != row.audit_year else int(row.audit_year),
            "nsloc": None if row.nsloc != row.nsloc else int(row.nsloc), "finding_id": row.finding_id, "title": row.title,
            "severity": row.severity, "group": row.vuln_group, "leaf": row.vuln_leaf, "confidence": round(float(row.vuln_confidence), 3),
            "needs_review": bool(row.vuln_needs_review), "files": files, "contracts": contracts, "functions": functions,
            "fn_contract": fn_contract, "root_cause": root, "root_cause_from": root_from, "impact": impact, "impact_from": impact_from,
            "poc": R.has_poc(body), "fix": R.has_diff(body) or bool(R.FIX_LINK.search(body)),
            "source_url": m.group(0) if (m := ISSUE_LINK.search(body)) else row.report_url,
            "code_url": f"https://github.com/{row.repo}/tree/{row.commit}" if row.repo and row.commit else None,
            "qa_leak": bool(QA_LEAK.search(body)), "body": body,
        })

    # Other findings in the same audit that name a common function.
    by_audit = {}
    for rec in records:
        by_audit.setdefault(rec["engagement_id"], []).append(rec)
    for rec in records:
        rec["look_alikes"] = [{"uid": o["uid"], "finding_id": o["finding_id"], "title": o["title"], "leaf": o["leaf"],
                               "shared": sorted(set(rec["functions"]) & set(o["functions"])), "same_class": o["leaf"] == rec["leaf"]}
                              for o in by_audit[rec["engagement_id"]] if o is not rec and set(rec["functions"]) & set(o["functions"])]
        flags = []
        if not rec["functions"]:
            flags.append("no function")
        if not [f for f in rec["files"] if not f["external"]]:
            flags.append("no file")
        if not rec["impact"]:
            flags.append("no impact section")
        if rec["root_cause_from"] == "title":
            flags.append("root cause = title")
        if rec["qa_leak"]:
            flags.append("QA report text in body")
        if len(rec["functions"]) > 8:
            flags.append("9+ functions")
        if rec["confidence"] < 0.85 or rec["needs_review"] or rec["group"] == "unclassified":
            flags.append("weak label")
        if any(l["same_class"] for l in rec["look_alikes"]):
            flags.append("same function + class as another finding")
        rec["flags"] = flags

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"findings": records}, separators=(",", ":"), default=str))
    n = len(records)
    count = lambda f: sum(f(r) for r in records)  # noqa: E731
    print(f"{n} findings in {len(by_audit)} audits -> {out}")
    print(f"file {count(lambda r: any(not f['external'] for f in r['files']))}, contract {count(lambda r: bool(r['contracts']))}, "
          f"function {count(lambda r: bool(r['functions']))}, impact {count(lambda r: bool(r['impact']))}")
    print("root cause from:", {k: count(lambda r, k=k: r["root_cause_from"] == k) for k in sorted({r["root_cause_from"] for r in records})})
    print("functions with a contract:", sum(1 for r in records for p in r["fn_contract"] if p["contract"]), "of", sum(len(r["functions"]) for r in records))
    print("flags:", {f: count(lambda r, f=f: f in r["flags"]) for f in sorted({f for r in records for f in r["flags"]})})


if __name__ == "__main__":
    main()
