"""Measure how agent-ready each audit's findings are, and write the dashboard datasets.

Per selected critical/high/medium finding with text, detects:
  functions  function names in the bug description (before any PoC test, mitigation or discussion); test helpers and builtins excluded
  attack     an explicit attack narrative section (attack path, exploit scenario, steps to reproduce...)
  poc        test code (function test…, #[test], vm.prank(…) anywhere in the text
  fix_diff   a diff in the text; fix_link: a link to a fix commit or pull request
Joins contest scope (nSLOC, repo, commit) from fetch_scope.py output when present.

    .venv/bin/python -I benchmark-review/readiness.py --release data/release --scope data/release/scope --out benchmark-review/datasets
"""
import argparse
import json
import re
from collections import Counter
from pathlib import Path

import duckdb
import pandas as pd

CODE_BLOCK = re.compile(r"```[^\n]*\n(.*?)```", re.S)
INLINE_CALL = re.compile(r"`(?:[A-Za-z_][\w]*(?:\.|::))?([A-Za-z_]\w*)\s*\([^`]*\)?`")
# Plain-text calls: qualified (Vault.withdraw(, Pool::swap() or identifier-shaped (camelCase / snake_case / _private).
PLAIN_CALL = re.compile(r"\b[A-Za-z_]\w*(?:\.|::)([A-Za-z_]\w*)\(|"
                        r"(?<![\w.])(_?[a-z][a-z0-9]*[A-Z][A-Za-z0-9]*|_?[a-z][a-z0-9]*(?:_[a-z0-9]+)+|_[A-Za-z]\w*|[a-z]{3,}(?=\(\)))\(")
DEF = re.compile(r"\b(?:function|fn|def|func|public fun|fun|entry fun)\s+([A-Za-z_]\w*)\s*[(<]")
NOT_FUNCTIONS = set("""require assert revert emit keccak256 sha256 ecrecover abi type address uint256 uint128 uint64 uint32 uint8
int256 bytes bytes32 bytes4 payable new return if for while mapping push pop length super this msg block tx log console
balanceOf transfer transferFrom approve totalSupply decimals allowance safeTransfer safeTransferFrom safeApprove
setUp constructor fallback receive main mul div add sub min max abs unchecked selector encode encodePacked decode call delegatecall
staticcall send unwrap wrap into unwrap_or expect ok err some none clone to_string from len iter map collect assert_eq println
assertEq assertTrue assertFalse assertGt assertGe assertLt assertLe assertApproxEqAbs assertApproxEqRel startPrank stopPrank prank
deal warp roll expectRevert expectEmit makeAddr label mockCall connect getSigners getContractAt encodeWithSelector
encodeWithSignature encodeCall toString log_named_uint""".split())
# Where the bug description ends: test code, mitigation/recommendation, or discussion and sponsor comments.
DESCRIPTION_END = re.compile(
    r"^\s*(?:#{1,6}\s*)?\**\s*(?:recommended mitigation(?: steps)?|mitigation|recommendations?|remediation|discussion|tools? used)\s*\**\s*:?\s*$|"
    r"^\s*\*\*\[[^\]\n]+\]\(", re.I | re.M)


def description(body):
    """The finding's text up to its PoC test, mitigation or discussion."""
    end = len(body)
    m = DESCRIPTION_END.search(body)
    if m:
        end = m.start()
    t = TEST_CODE.search(body)
    if t and t.start() < end:
        fence = body.rfind("```", 0, t.start())
        line = body.rfind("\n", 0, t.start()) + 1
        end = fence if fence >= 0 and body.count("```", 0, t.start()) % 2 == 1 else line
    return body[:end]
TEST_NAME = re.compile(r"^(test|invariant|fuzz|setup|testFail|poc|it|describe|exploit|attack)", re.I)
# An attack narrative section: a markdown heading, or (PDF text) a line that is only the heading.
ATTACK_HEADING = re.compile(r"^\s*(?:#{1,6}\s*)?\**\s*(attack (path|scenario|vector|flow|steps)|exploit(ation)?( scenario| path| steps)?|"
                            r"(proof of concept|poc) (steps|scenario|walkthrough)|steps to reproduce|(example |attack )?scenarios?|"
                            r"how (an )?attacker[^\n]{0,40})\s*\**\s*:?\s*$", re.I | re.M)
TEST_CODE = re.compile(r"function\s+test\w*\s*\(|#\[test\]|#\[tokio::test\]|\bvm\.(prank|startPrank|warp|deal|expectRevert|roll)\(|"
                       r"\bit\(\s*['\"]|describe\(\s*['\"]|forge test|def test_\w+\(|assertEq\(", re.I)
FIX_LINK = re.compile(r"https://github\.com/[^\s)\]]+/(?:commit|pull)/[0-9a-zA-Z]+")


def functions_in(body):
    body = description(body)
    names = set()
    for m in INLINE_CALL.finditer(body):
        names.add(m.group(1))
    prose = CODE_BLOCK.sub(" ", body)
    for m in PLAIN_CALL.finditer(prose):
        names.add(m.group(1) or m.group(2))
    for block in CODE_BLOCK.findall(body):
        names.update(DEF.findall(block))
        if not TEST_CODE.search(block):  # calls in snippets of the audited code, not in PoC tests
            names.update(m.group(1) or m.group(2) for m in PLAIN_CALL.finditer(block))
    names.update(DEF.findall(prose))
    return sorted(n for n in names if n not in NOT_FUNCTIONS and not TEST_NAME.match(n) and len(n) > 2 and not n[0].isupper())


PATCH_LINE = re.compile(r"^\s*([+-])(?![+-])\s{0,3}\S", re.M)


def has_diff(body):
    if "```diff" in body:
        return True
    for block in CODE_BLOCK.findall(body):
        signs = [m.group(1) for m in PATCH_LINE.finditer(block)]
        if signs.count("+") and signs.count("-") and len(signs) >= 2:
            return True
    return False


def has_poc(body):
    return bool(TEST_CODE.search(body))


def load_scope(scope_dir):
    rows = []
    for path in Path(scope_dir).glob("*.json"):
        if path.name.endswith(".error.json"):
            continue
        rec = json.loads(path.read_text())
        repo = (rec.get("repos") or [{}])[0]
        sherlock = rec.get("platform") == "sherlock"
        rows.append({
            "engagement_id": rec["engagement_id"], "contest_key": str(rec["contest_id"]), "nsloc": rec.get("nsloc"),
            "nsloc_method": rec.get("nsloc_method"), "scope_files": len(rec.get("files") or []),
            "repo": repo.get("repo"), "commit": repo.get("commit"), "n_repos": len(rec.get("repos") or []),
            # Sherlock's own contest title and end year, which correct a few mis-parsed corpus project names and missing years.
            "contest_title": rec.get("title") if sherlock else None,
            "contest_year": pd.Timestamp(rec["ends_at"], unit="s").year if sherlock and rec.get("ends_at") else None,
        })
    return pd.DataFrame(rows)


def apply_contest_names(frame):
    """Prefer the platform's contest title and fill a missing year from the contest end date."""
    frame["project"] = frame.contest_title.where(frame.contest_title.notna(), frame.project)
    frame["audit_year"] = frame.audit_year.where(frame.audit_year.notna(), frame.contest_year)
    return frame.drop(columns=["contest_title", "contest_year"])


def write(out, name, rows, meta):
    meta = meta + [
        {"label": "Input", "value": "Web3 Audit Corpus v1.3.0 release (findings.parquet, engagements.csv); contest scope from fetch_scope.py"},
        {"label": "readiness.py", "value": Path(__file__).read_text(), "type": "code", "lang": "python"},
    ]
    path = out / f"{name}.json"
    path.write_text(json.dumps({"rows": rows, "meta": meta}, separators=(",", ":"), default=str))
    return path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    ap.add_argument("--scope", default="data/release/scope")
    ap.add_argument("--out", default="benchmark-review/datasets")
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    c = duckdb.connect()
    c.execute(f"create view e as select * from read_csv_auto('{args.release}/engagements.csv', all_varchar=true)")
    c.execute(f"create view f as select * from '{args.release}/findings.parquet'")
    df = c.execute(
        """select f.finding_uid, f.engagement_id, f.firm_id, f.severity, f.vuln_group, f.vuln_leaf, f.body_text,
                  e.review_mode, e.project, try_cast(e.audit_year as int) audit_year, e.languages
           from f join e using(engagement_id)
           where f.selected_for_stats and f.severity in ('critical','high','medium') and f.body_text_status = 'present'"""
    ).df()
    total_chm = c.execute("select count(*) from f where selected_for_stats and severity in ('critical','high','medium')").fetchone()[0]

    df["functions"] = df.body_text.map(functions_in)
    df["has_functions"] = df.functions.map(bool)
    df["attack"] = df.body_text.map(lambda b: bool(ATTACK_HEADING.search(b)))
    df["security_class"] = df.vuln_group.notna() & ~df.vuln_group.isin(["quality", "gas", "unclassified"])
    df["poc"] = df.body_text.map(has_poc)
    df["fix_diff"] = df.body_text.map(has_diff)
    df["fix_link"] = df.body_text.map(lambda b: bool(FIX_LINK.search(b)))
    df["fix"] = df.fix_diff | df.fix_link
    df["complete"] = df.has_functions & df.attack & df.poc & df.fix
    df["platform"] = df.firm_id.where(df.review_mode == "contest", "firm reviews")
    df.loc[(df.review_mode == "contest") & ~df.firm_id.isin(["sherlock", "code4rena", "cantina"]), "platform"] = "other contests"
    signals = ["has_functions", "attack", "poc", "fix_diff", "fix_link", "fix", "complete"]

    # 1. Requirement coverage by platform.
    by_platform = []
    for plat, g in list(df.groupby("platform")) + [("all", df)]:
        row = {"platform": plat, "findings": int(len(g)), "audits": int(g.engagement_id.nunique())}
        for s in signals:
            row[f"pct_{s}"] = round(100 * g[s].mean(), 1)
        by_platform.append(row)
    by_platform.sort(key=lambda r: (r["platform"] == "all", -r["findings"]))
    write(out, "coverage_by_platform", by_platform, [
        {"label": "Findings", "value": "Selected critical, high and medium findings with full text"},
        {"label": "Findings without text (excluded)", "value": str(total_chm - len(df))},
    ])

    # 2. Per-audit table with scope joined.
    scope = load_scope(args.scope) if Path(args.scope).exists() else pd.DataFrame(columns=["engagement_id"])
    agg = df.groupby("engagement_id").agg(
        platform=("platform", "first"), project=("project", "first"), audit_year=("audit_year", "first"),
        chm=("finding_uid", "size"), critical=("severity", lambda s: int((s == "critical").sum())),
        high=("severity", lambda s: int((s == "high").sum())), medium=("severity", lambda s: int((s == "medium").sum())),
        with_functions=("has_functions", "sum"), with_attack=("attack", "sum"), with_poc=("poc", "sum"),
        with_fix=("fix", "sum"), complete=("complete", "sum"),
        functions=("functions", lambda col: len({f for fs in col for f in fs})),
        classes=("vuln_leaf", lambda s: int(s.nunique())),
    ).reset_index()
    agg = apply_contest_names(agg.merge(scope, on="engagement_id", how="left"))
    agg["has_scope"] = agg.nsloc.notna() & (agg.nsloc > 0) & agg.commit.notna()
    agg["chm_per_kloc"] = (agg.chm / agg.nsloc * 1000).round(1)
    agg["all_functions"] = agg.with_functions == agg.chm
    agg["contest_url"] = [
        f"https://audits.sherlock.xyz/contests/{k}" if p == "sherlock" else f"https://code4rena.com/reports/{k}" if p == "code4rena" else None
        for p, k in zip(agg.platform, agg.contest_key)]
    agg["code_url"] = [f"https://github.com/{r}/tree/{c}" if isinstance(r, str) and isinstance(c, str) else None
                       for r, c in zip(agg.repo, agg.commit)]
    contests = agg[agg.platform.isin(["sherlock", "code4rena"])].copy()

    # 3. Funnel over contest audits; each stage keeps the previous stage's filters.
    s1 = contests
    s2 = s1[s1.has_scope]
    s3 = s2[s2.chm >= 3]
    s4 = s3[s3.all_functions]
    s5 = s4[s4.nsloc < 2000]
    s6 = s5[s5.nsloc < 1000]
    stages = [
        ("Sherlock and Code4rena contests with findings", s1),
        ("Scope size and audited commit found", s2),
        ("3+ critical/high/medium findings", s3),
        ("Every one of them names a function", s4),
        ("Under 2,000 nSLOC", s5),
        ("Under 1,000 nSLOC", s6),
    ]
    funnel = [{"step": i + 1, "stage": name, "audits": int(len(g)), "findings": int(g.chm.sum()),
               "with_poc": int(g.with_poc.sum()), "with_fix": int(g.with_fix.sum())} for i, (name, g) in enumerate(stages)]
    write(out, "contest_funnel", funnel, [
        {"label": "Scope sizes", "value": "Sherlock contest API nsloc; Code4rena audit-repo README scope tables (fetch_scope.py)"},
        {"label": "Function names", "value": "Function names in inline code, plain-text calls or code snippets (readiness.py)"},
    ])

    # 4. nSLOC distribution for contests with scope.
    bins = [0, 500, 1000, 1500, 2000, 3000, 5000, 10**9]
    labels = ["<500", "500–1k", "1k–1.5k", "1.5k–2k", "2k–3k", "3k–5k", "5k+"]
    sized = contests[contests.has_scope].copy()
    sized["bucket"] = pd.cut(sized.nsloc, bins=bins, labels=labels, right=False)
    loc_rows = []
    for lab in labels:
        g = sized[sized.bucket == lab]
        n = g.chm.sum()
        loc_rows.append({"bucket": lab, "audits": int(len(g)), "findings": int(n),
                         "median_chm": float(g.chm.median()) if len(g) else 0.0,
                         "pct_functions": round(100 * g.with_functions.sum() / n, 1) if n else 0.0,
                         "pct_poc": round(100 * g.with_poc.sum() / n, 1) if n else 0.0})
    write(out, "nsloc_buckets", loc_rows, [{"label": "Audits", "value": "Sherlock and Code4rena contests with a scope size and commit"}])

    # 5. Candidate audits: contests with scope, 3+ C/H/M, smallest first.
    cand = s3.sort_values(["nsloc", "chm"], ascending=[True, False]).copy()
    cols = ["engagement_id", "platform", "contest_key", "project", "audit_year", "nsloc", "nsloc_method", "chm", "critical", "high",
            "medium", "chm_per_kloc", "with_functions", "all_functions", "with_attack", "with_poc", "with_fix", "complete", "classes",
            "repo", "commit", "contest_url", "code_url"]
    cand_rows = json.loads(cand[cols].to_json(orient="records"))
    write(out, "candidate_audits", cand_rows, [
        {"label": "Included", "value": "Sherlock and Code4rena contests with a scope size, audited commit and 3+ critical/high/medium findings with text"},
        {"label": "Counts", "value": "with_* columns count critical/high/medium findings that meet each requirement"},
        {"label": "Complete", "value": "Function names, attack narrative, PoC test and a fix (diff or fix commit/PR)"},
    ])

    # 6. Overall headline numbers.
    headline = [{
        "chm_findings": int(total_chm), "chm_with_text": int(len(df)), "audits_with_chm": int(df.engagement_id.nunique()),
        "pct_functions": round(100 * df.has_functions.mean(), 1), "pct_attack": round(100 * df.attack.mean(), 1),
        "pct_poc": round(100 * df.poc.mean(), 1), "pct_fix": round(100 * df.fix.mean(), 1),
        "pct_complete": round(100 * df.complete.mean(), 1), "complete_findings": int(df.complete.sum()),
        "contests_with_scope": int(contests.has_scope.sum()), "contests": int(len(contests)),
        "median_functions_per_finding": float(df.functions.map(len)[df.has_functions].median()),
    }]
    write(out, "headline", headline, [{"label": "Scope", "value": "All publishers; critical, high and medium; selected findings"}])

    # 7. Root-cause groups among the findings of the under-2,000-nSLOC shortlist.
    cls = Counter(df[df.engagement_id.isin(s5.engagement_id)].vuln_group.fillna("unlabelled"))
    write(out, "shortlist_classes", [{"vuln_group": k, "findings": v} for k, v in cls.most_common()],
          [{"label": "Findings", "value": "Critical/high/medium findings of the audits in funnel step 5 (under 2,000 nSLOC)"},
           {"label": "Class", "value": "Corpus root-cause group, one per finding (LLM-assigned)"}])

    print(json.dumps(headline[0], indent=1))
    print(pd.DataFrame(by_platform).to_string(index=False))
    print(pd.DataFrame(funnel).to_string(index=False))
    print(pd.DataFrame(loc_rows).to_string(index=False))
    print(cand[cols[1:-2]].head(15).to_string(index=False))


if __name__ == "__main__":
    main()
