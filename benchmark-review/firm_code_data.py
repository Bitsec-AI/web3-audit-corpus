"""Review records for Spearbit/Cantina audits whose findings are located in public code, with fix patches.

Audits: code at the audit commit is public (or has a public copy), the audit is not a Cantina copy of a Spearbit audit,
it has at least --min-findings critical/high/medium findings and at least --min-located of them are located to file and
lines (see fetch_report_links.py, whose output this reads).

Per finding:
  - Functions and contracts come from the code: each located file is fetched at the audit commit and the function and
    contract enclosing the Context lines are found by matching braces (indentation for Vyper/Python).
  - Fixes: "Fixed in PR 40" / "commit 7463cea3" replies after the Recommendation are matched to the PR and commit links
    of the report (or the audited repo when the report has no such link), and each fix diff is saved as a patch.

Everything else (root cause, impact, class, flags) comes from review_data.build.

    .venv/bin/python -I benchmark-review/firm_code_data.py --release data/release --links data/release/report_links
"""
import argparse
import json
import re
import shutil
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import review_data  # noqa: E402

UA = "web3-audit-corpus-research (fix patches)"
MAX_PATCH = 5_000_000  # bytes; larger diffs (vendored dependencies, build output) are kept on disk but not used
BRACE_LANGS = {"sol", "rs", "go", "move", "cairo", "ts", "js", "cpp", "hpp", "cc", "c", "h", "nr", "circom", "yul", "java", "kt", "swift", "zig"}
FUNCTION = {
    "sol": r"\b(?:function|modifier)\s+(\w+)\s*\(|\b(constructor|fallback|receive)\s*\(",
    "rs": r"\bfn\s+(\w+)\s*[<(]", "nr": r"\bfn\s+(\w+)\s*[<(]", "cairo": r"\b(?:fn|func)\s+(\w+)\s*[<({]",
    "go": r"\bfunc\s+(?:\(\s*\w*\s*\*?\s*(\w+)[^)]*\)\s*)?(\w+)\s*[\[(]",
    "move": r"\bfun\s+(\w+)\s*[<(]", "circom": r"\b(?:template|function)\s+(\w+)\s*\(", "yul": r"\bfunction\s+(\w+)\s*\(",
    "ts": r"\bfunction\s+(\w+)|^[ \t]*(?:(?:public|private|protected|static|async|override)\s+)*(\w+)\s*\([^)]*\)\s*(?::[^{;]+)?\{",
    "cpp": r"\b(\w+)\s*\([^;{}]*\)\s*(?:const\s*)?(?:noexcept\s*)?(?:override\s*)?(?:->\s*[\w:<>]+\s*)?\{",
    "py": r"^[ \t]*def\s+(\w+)\s*\(",
}
for ext, lang in {"js": "ts", "hpp": "cpp", "cc": "cpp", "c": "cpp", "h": "cpp", "vy": "py"}.items():
    FUNCTION[ext] = FUNCTION[lang]
CONTAINER = {
    "sol": r"\b(?:abstract\s+)?(?:contract|library|interface)\s+(\w+)",
    "rs": r"\bimpl(?:\s*<[^{]*?>)?\s+(?:[\w:]+(?:<[^{]*?>)?\s+for\s+)?(?:[\w]+::)*(\w+)|\b(?:mod|trait)\s+(\w+)",
    "move": r"\bmodule\s+(?:[\w:]+::)?(\w+)", "cairo": r"\b(?:mod|impl|trait)\s+(\w+)", "ts": r"\bclass\s+(\w+)",
    "cpp": r"\b(?:class|struct|namespace)\s+(\w+)[^;{(]*\{", "nr": r"\b(?:impl|mod|trait)\s+(\w+)",
}
for ext, lang in {"js": "ts", "hpp": "cpp", "cc": "cpp", "c": "cpp", "h": "cpp"}.items():
    CONTAINER[ext] = CONTAINER[lang]
NOT_FUNCTIONS = {"if", "for", "while", "switch", "catch", "return", "sizeof", "require", "assert", "emit", "revert", "new", "else"}
COMMENT = re.compile(r"//[^\n]*|/\*.*?\*/|\"(?:[^\"\\\n]|\\.)*\"", re.S)
PY_COMMENT = re.compile(r"#[^\n]*|\"\"\".*?\"\"\"|'''.*?'''", re.S)
PR_REF = re.compile(r"(?i)\b(?:PRs?|pull requests?)\b\s*((?:#?\s*\d+\b(?:\s*(?:,|and|&|/)\s*(?:PRs?\s*)?)?)+)")
COMMIT_REF = re.compile(r"(?i)\bcommits?\b((?:[\s,:#]*(?:and\s+)?`?[0-9a-f]{7,40}\b`?)+)")
URL_REF = re.compile(r"github\.com/([\w.-]+/[\w.-]+?)/(pull|commit)/(\w+)")


def blank(m):
    return re.sub(r"[^\n]", " ", m.group(0))


def block_end(src, i):
    """Index after the brace block that starts at the first '{' after i, or None if a ';' comes first at depth 0."""
    paren = 0
    while i < len(src):
        ch = src[i]
        if ch in "([":
            paren += 1
        elif ch in ")]":
            paren -= 1
        elif ch == ";" and paren <= 0:
            return None
        elif ch == "{" and paren <= 0:
            break
        i += 1
    depth = 0
    for j in range(i, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return j + 1
    return None


def spans(src, pattern, ext):
    """(name, first line, last line, receiver) for each definition matching pattern."""
    line_at = lambda pos: src.count("\n", 0, pos) + 1  # noqa: E731
    out = []
    for m in re.finditer(pattern, src, re.M):
        groups = [g for g in m.groups() if g]
        if not groups:
            continue
        name, receiver = groups[-1], (groups[0] if ext == "go" and len(groups) == 2 else None)
        if name in NOT_FUNCTIONS:
            continue
        if ext in ("py", "vy"):
            indent = len(m.group(0)) - len(m.group(0).lstrip())
            lines = src[m.start():].split("\n")
            n = 1
            for ln in lines[1:]:
                if ln.strip() and len(ln) - len(ln.lstrip()) <= indent:
                    break
                n += 1
            out.append((name, line_at(m.start()), line_at(m.start()) + n - 1, receiver))
            continue
        end = block_end(src, m.end() - 1 if src[m.end() - 1] in "{(" else m.end())
        if end:
            out.append((name, line_at(m.start()), line_at(end - 1), receiver))
    return out


def enclosing(source, path, start, end):
    """Functions overlapping lines start..end (innermost first) and their contracts; ([], contract or None) outside functions."""
    ext = path.rsplit(".", 1)[-1].lower()
    if ext not in FUNCTION:
        return [], None
    src = (PY_COMMENT if ext in ("py", "vy") else COMMENT).sub(blank, source)
    fns = spans(src, FUNCTION[ext], ext)
    boxes = spans(src, CONTAINER[ext], ext) if ext in CONTAINER else []
    box_of = lambda line: min((b for b in boxes if b[1] <= line <= b[2]), key=lambda b: b[2] - b[1], default=None)  # noqa: E731
    if start is None:
        names = {b[0] for b in boxes}
        return [], names.pop() if len(names) == 1 else None
    end = end or start
    hits = [f for f in fns if f[1] <= end and f[2] >= start]
    hits = [f for f in hits if not any(g is not f and f[1] <= g[1] and g[2] <= f[2] and g[1] <= start <= g[2] for g in hits)]
    if not hits:
        b = box_of(start)
        return [], b[0] if b else None
    out = []
    for name, first, _, receiver in sorted(hits, key=lambda f: f[1]):
        b = box_of(first)
        out.append({"function": name, "contract": receiver or (b[0] if b else None), "line": first})
    return out, None


def get(url, path):
    if path.exists():
        return path.read_text(errors="replace") if path.stat().st_size else None
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        req = urllib.request.Request(urllib.parse.quote(url, safe=":/%?=&#@"), headers={"User-Agent": UA})
        data = urllib.request.urlopen(req, timeout=60).read()
        time.sleep(0.2)
    except Exception as exc:
        print("fetch fail", url, exc, flush=True)
        data = b""
    path.write_bytes(data)
    return data.decode(errors="replace") or None


def gh_diff(endpoint, path):
    """Save a pull request or commit diff from the GitHub API; returns a status."""
    if path.exists():
        return "ok" if path.stat().st_size else path.with_suffix(".err").read_text()
    res = subprocess.run(["gh", "api", "-H", "Accept: application/vnd.github.diff", endpoint], capture_output=True)
    time.sleep(0.3)
    if res.returncode == 0 and res.stdout:
        path.write_bytes(res.stdout)
        return "ok"
    err = res.stderr.decode(errors="replace")
    status = "too_large" if "too large" in err.lower() or "406" in err else "not_found" if "404" in err else "error"
    if "rate limit" in err.lower():
        raise SystemExit("GitHub rate limit; rerun later (diffs are cached)")
    path.write_bytes(b"")
    path.with_suffix(".err").write_text(status)
    return status


def fix_refs(body):
    """PR numbers and commit hashes the finding's fix replies name (text after the Recommendation, if any)."""
    i = body.rfind("Recommendation")
    tail = body[i:] if i >= 0 else body
    prs, commits = [], []
    for m in PR_REF.finditer(tail):
        prs += [int(n) for n in re.findall(r"\d+", m.group(1))]
    for m in COMMIT_REF.finditer(tail):
        commits += [h.lower() for h in re.findall(r"[0-9a-fA-F]{7,40}", m.group(1))]
    urls = [(repo.lower(), kind, ref) for repo, kind, ref in URL_REF.findall(tail)]
    return list(dict.fromkeys(prs)), list(dict.fromkeys(commits)), urls


def diff_stats(text):
    files = re.findall(r"^diff --git a/(\S+) b/", text, re.M)
    return {"files": files, "additions": len(re.findall(r"^\+(?!\+\+ )", text, re.M)),
            "deletions": len(re.findall(r"^-(?!-- )", text, re.M))}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    ap.add_argument("--scope", default="data/release/scope")
    ap.add_argument("--links", default="data/release/report_links")
    ap.add_argument("--min-findings", type=int, default=3)
    ap.add_argument("--min-located", type=float, default=0.8)
    ap.add_argument("--out", default=str(HERE / "review" / "firm_code.json"))
    args = ap.parse_args()
    links = Path(args.links)
    eng = {e["engagement_id"]: e for e in json.loads((links / "engagements.json").read_text())}
    chosen = {eid for eid, e in eng.items() if e["code_available"] and not e["republishes_spearbit"]
              and e["hcm"] >= args.min_findings and e["hcm_located"] >= args.min_located * e["hcm"]}
    located = {f["finding_uid"]: f for f in json.loads((links / "findings.json").read_text()) if f["engagement_id"] in chosen}
    print(f"{len(chosen)} audits", flush=True)

    # code files at the audit commit
    def fetch_repo(e, repo, sha):
        c = next((x for x in e["commits"] if x["repo"] == repo and x["sha"] == sha), None)
        if not c or c["status"] not in ("public", "public_copy"):
            return None, None
        return c.get("copy_repo") or repo, c["full_sha"]
    jobs = {}
    for f in located.values():
        for loc in f["locations"]:
            if loc.get("repo"):
                repo, full = fetch_repo(eng[f["engagement_id"]], loc["repo"], loc["sha"])
                if repo:
                    loc["fetch"] = [repo, full]
                    jobs[(repo, full, loc["path"])] = links / "code" / f"{repo.replace('/', '__')}@{full[:12]}" / loc["path"]
    with ThreadPoolExecutor(4) as pool:
        src = dict(zip(jobs, pool.map(lambda kv: get(f"https://raw.githubusercontent.com/{kv[0][0]}/{kv[0][1]}/{kv[0][2]}", kv[1]),
                                      jobs.items())))
    print(f"{sum(v is not None for v in src.values())}/{len(src)} code files fetched", flush=True)

    # fix diffs
    patch_dir = links / "patches"
    patch_dir.mkdir(exist_ok=True)
    review_patches = Path(args.out).parent / "patches"  # the review app reads patches through this link
    if review_patches.is_dir() and not review_patches.is_symlink():
        shutil.rmtree(review_patches)
    if not review_patches.exists():
        review_patches.symlink_to(patch_dir.resolve())

    def fixes_for(e, body):
        prs, commits, urls = fix_refs(body)
        audited = e.get("audited_repos") or e["repos"]
        copy = {x["repo"]: x["copy_repo"] for x in e["commits"] if x.get("copy_repo")}
        out = []
        refs = [("pull", repo, ref) for repo, kind, ref in urls if kind == "pull"] + \
               [("commit", repo, ref) for repo, kind, ref in urls if kind == "commit"]
        for n in prs:
            repos = sorted({p.split("#")[0] for p in e["prs"] if p.endswith(f"#{n}")}, key=lambda r: audited.index(r) if r in audited else 99)
            refs.append(("pull", repos[0] if repos else (audited[0] if audited else None), str(n)) + (() if repos else ("inferred",)))
        for h in commits:
            hits = [c for c in e["fix_commits"] if c.split("@")[1].startswith(h) or h.startswith(c.split("@")[1])]
            refs.append(("commit", hits[0].split("@")[0] if hits else (audited[0] if audited else None), h) + (() if hits else ("inferred",)))
        seen = set()
        for kind, repo, ref, *inferred in refs:
            if not repo or (kind, repo, ref) in seen:
                continue
            seen.add((kind, repo, ref))
            name = f"{repo.replace('/', '__')}__{kind}_{ref}.diff"
            status = gh_diff(f"repos/{repo}/{'pulls' if kind == 'pull' else 'commits'}/{ref}", patch_dir / name)
            source = repo
            if status != "ok" and kind == "commit" and repo in copy:  # a fork keeps commit hashes
                status = gh_diff(f"repos/{copy[repo]}/commits/{ref}", patch_dir / name.replace(".diff", "_copy.diff"))
                name = name.replace(".diff", "_copy.diff")
                source = copy[repo] if status == "ok" else repo
            rec = {"kind": kind, "repo": repo, "ref": ref, "inferred_repo": bool(inferred), "status": status,
                   "url": f"https://github.com/{source}/{kind}/{ref}"}
            if source != repo:
                rec["copy_repo"] = source
            if status == "ok" and (patch_dir / name).stat().st_size > MAX_PATCH:
                status = rec["status"] = "too_large"
            if status == "ok":
                text = (patch_dir / name).read_text(errors="replace")
                rec.update(diff_stats(text), patch=f"patches/{name}")
            out.append(rec)
        return out

    def overlay(records):
        for n, rec in enumerate(records, 1):
            f, e = located.get(rec["uid"]), eng[rec["engagement_id"]]
            rec["functions_text"] = rec["functions"]
            files, locs, pairs, contracts = {}, [], [], []
            for loc in (f or {}).get("locations", []):
                path, start, end = loc.get("path") or loc["file"], loc["start"], loc["end"]
                where = {"path": path, "start": start, "end": end, "method": loc["method"], "functions": [], "contract": None}
                text = src.get((loc["fetch"][0], loc["fetch"][1], path)) if loc.get("fetch") else None
                if loc.get("fetch"):
                    lines = f"#L{start}" + (f"-L{end}" if end and end != start else "") if start else ""
                    where["url"] = f"https://github.com/{loc['fetch'][0]}/blob/{loc['fetch'][1]}/{path}{lines}"
                if text:
                    fns, box = enclosing(text, path, start, end)
                    where["functions"], where["contract"] = fns, box
                    for p in fns:
                        if p["function"] not in [q["function"] for q in pairs]:
                            pairs.append({"function": p["function"], "contract": p["contract"]})
                    contracts += [p["contract"] for p in fns if p["contract"]] + ([box] if box else [])
                where["code"] = "fetched" if text else "unavailable" if loc.get("fetch") else "not located"
                locs.append(where)
                name = path.split("/")[-1]
                files.setdefault(name, {"name": name, "path": path, "how": "code" if text else "mention", "external": False, "in_scope": None})
            if locs:
                rec["files"], rec["fn_contract"] = list(files.values()), pairs
                rec["functions"] = [p["function"] for p in pairs]
                rec["contracts"] = list(dict.fromkeys(contracts))
            rec["locations"] = locs
            scope = e["scope_commit"]
            rec["code_url"] = f"https://github.com/{scope.get('copy_repo') or scope['repo']}/tree/{scope['full_sha']}"
            rec["fixes"] = fixes_for(e, rec["body"] or "")
            rec["fix"] = rec["fix"] or any(x["status"] == "ok" for x in rec["fixes"])
            names = {l["path"].split("/")[-1] for l in locs}
            for x in rec["fixes"]:
                if x["status"] == "ok":
                    x["touches_finding_file"] = any(p.split("/")[-1] in names for p in x["files"])
            if n % 100 == 0:
                print(f"{n}/{len(records)} findings", flush=True)

    records = review_data.build(args.release, args.scope, sorted(chosen), overlay=overlay)
    for rec in records:
        if rec["locations"] and any(l["code"] == "fetched" and not l["functions"] and l["start"] for l in rec["locations"]):
            rec["flags"].append("a location is outside any function")
        if not any(x["status"] == "ok" for x in rec["fixes"]):
            rec["flags"].append("no fix patch")
        elif not any(x.get("touches_finding_file") for x in rec["fixes"]):
            rec["flags"].append("patch misses the finding's files")
    review_data.write(records, args.out)
    fixes = [x for r in records for x in r["fixes"]]
    count = lambda k: sum(k(r) for r in records)  # noqa: E731
    print(f"function from code {count(lambda r: any(l['functions'] for l in r['locations']))}, "
          f"fix ref {count(lambda r: bool(r['fixes']))}, patch {count(lambda r: any(x['status'] == 'ok' for x in r['fixes']))}, "
          f"patch touching finding file {count(lambda r: any(x.get('touches_finding_file') for x in r['fixes']))}")
    print("fix refs:", {s: sum(x["status"] == s for x in fixes) for s in sorted({x["status"] for x in fixes})},
          "inferred repo:", sum(x["inferred_repo"] for x in fixes))


if __name__ == "__main__":
    main()
