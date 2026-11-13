"""Fetch contest scope size (nSLOC), scoped files and audited commit for Sherlock and Code4rena.

Sherlock: the public contest API (audits.sherlock.xyz/api/contests/<id>).
Code4rena: the README of the code-423n4/<contest> audit repo, via the GitHub API, parsed for
its scope table's SLOC column.

Responses are cached as JSON under --out, one file per contest; reruns skip cached contests.
At most one request per second.

    .venv/bin/python -I benchmark-review/fetch_scope.py --release data/release --out data/release/scope
"""
import argparse
import base64
import json
import re
import subprocess
import time
import urllib.request
from pathlib import Path

import duckdb

UA = "web3-audit-corpus-research (benchmark scope sizes)"
DELAY = 1.0


def sherlock_ids(c):
    rows = c.execute(
        """select distinct r.engagement_id, regexp_extract(r.url, 'contests/([0-9]+)', 1) id
           from r join e using(engagement_id)
           where r.firm_id = 'sherlock' and e.review_mode = 'contest' and r.url like '%audits.sherlock.xyz/contests/%'"""
    ).fetchall()
    return [(eng, int(i)) for eng, i in rows if i]


def code4rena_repos(c):
    rows = c.execute(
        """select distinct r.engagement_id, r.url from r join e using(engagement_id)
           where r.firm_id = 'code4rena' and e.review_mode = 'contest'"""
    ).fetchall()
    out = {}
    for eng, url in rows:
        m = re.search(r"code-423n4/([0-9]{4}-[0-9]{2}-[A-Za-z0-9._-]+?)-findings", url) or re.search(r"code4rena\.com/reports/([0-9]{4}-[0-9]{2}-[A-Za-z0-9._-]+)", url)
        if m:
            out.setdefault(eng, m.group(1))
    return sorted(out.items())


def fetch_sherlock(cid):
    req = urllib.request.Request(f"https://audits.sherlock.xyz/api/contests/{cid}", headers={"User-Agent": UA})
    data = json.loads(urllib.request.urlopen(req, timeout=30).read())
    data.pop("report", None)
    data.pop("description", None)
    files = [{"repo": s.get("repo"), "name": f["name"], "nsloc": f.get("nsloc")} for s in data.get("scope") or [] for f in s.get("files") or []]
    return {
        "platform": "sherlock", "contest_id": cid, "title": data.get("title"), "nsloc": data.get("nsloc"), "nsloc_method": "sherlock_api",
        "repos": [{"repo": s.get("repo"), "commit": s.get("commit_hash"), "nsloc": s.get("total_nsloc")} for s in data.get("scope") or []],
        "files": files, "template_repo": data.get("template_repo_name"), "languages": data.get("languages"),
        "starts_at": data.get("starts_at"), "ends_at": data.get("ends_at"),
    }


def gh_api(path):
    res = subprocess.run(["gh", "api", path], capture_output=True, text=True, timeout=60)
    if res.returncode != 0:
        raise RuntimeError(res.stderr.strip()[:200])
    return json.loads(res.stdout)


SOURCE_FILE = re.compile(r"[\w./-]+\.(?:sol|vy|rs|move|cairo|go|huff|yul|nr|circom)\b")
OUT_OF_SCOPE = re.compile(r"not in scope|out of scope|out-of-scope|excluded|context only", re.I)
SIZE_COLUMNS = [("nsloc", r"n?sloc"), ("cloc_code", r"code"), ("lines", r"(?:lines(?: of code)?|loc|line count|lines count)")]


def parse_sloc_tables(readme):
    """Size of the in-scope source files listed in a Code4rena README; returns (total, files, method).

    Reads markdown tables with an nSLOC/SLOC, cloc 'code' or 'lines' column, '### File.sol' headings
    followed by '**SLOC**: N', then '* File.sol (N lines)' bullet lists, skipping out-of-scope sections.
    """
    lines = readme.splitlines()
    found = {}
    heading = ""
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.lstrip().startswith("#"):
            heading = line
            m = re.search(r"\(\s*(?:n?sloc|loc|lines)\s*:?\s*([\d,]+)\s*\)|\(\s*([\d,]+)\s*(?:n?sloc|loc|lines)\s*\)", line, re.I)
            if m and not OUT_OF_SCOPE.search(line):
                name = re.sub(r"[#*`\[\]]|\(.*", "", line).strip()
                found.setdefault("heading_count", {})[name] = int((m.group(1) or m.group(2)).replace(",", ""))
        if line.strip().startswith("|") and i + 1 < len(lines) and re.match(r"^\s*\|?\s*:?-{2,}", lines[i + 1]):
            header = [re.sub(r"[*`_]", "", h).strip().lower() for h in line.strip().strip("|").split("|")]
            skip = bool(OUT_OF_SCOPE.search(heading))
            col = method = None
            for name, pattern in SIZE_COLUMNS:
                col = next((k for k, h in enumerate(header) if re.fullmatch(pattern, h)), None)
                if col is not None:
                    method = name
                    break
            i += 2
            while i < len(lines) and lines[i].strip().startswith("|"):
                cells = [x.strip() for x in lines[i].strip().strip("|").split("|")]
                path = next((p for k, cell in enumerate(cells) if k != col
                             for p in [SOURCE_FILE.search(re.sub(r"\(http[^)]*\)", "", cell))] if p), None) or \
                    next((p for k, cell in enumerate(cells) if k != col for p in [SOURCE_FILE.search(cell)] if p), None)
                if not skip and col is not None and col < len(cells) and path:
                    num = re.sub(r"[^\d]", "", cells[col])
                    if num:
                        found.setdefault(method, {})[path.group(0)] = int(num)
                i += 1
            continue
        if not OUT_OF_SCOPE.search(heading):
            m = re.match(r"^\s*(?:[-*]\s*)?\**\s*n?sloc\s*\**\s*:\s*\**\s*([\d,]+)", line, re.I)
            if m and heading:
                path = SOURCE_FILE.search(re.sub(r"\(http[^)]*\)", "", heading))
                name = path.group(0) if path else re.sub(r"[#*`\[\]]|\(.*", "", heading).strip()
                if name:
                    found.setdefault("heading_sloc", {})[name] = int(m.group(1).replace(",", ""))
            m = re.search(r"`?([\w./-]+\.(?:sol|vy|rs|move|cairo))`?\s*[-–:]\s*([\d,]+)\s*(?:n?sloc|loc|lines)\b", line, re.I)
            if m:
                found.setdefault("inline_loc", {})[m.group(1)] = int(m.group(2).replace(",", ""))
            m = re.match(r"^\s*[-*]\s*\[?`?([\w./-]+\.(?:sol|vy|rs|move|cairo))`?\]?(?:\([^)]*\))?\s*\(\s*([\d,]+)\s*(?:lines|loc|sloc|nsloc)", line, re.I)
            if m:
                found.setdefault("bullet_lines", {})[m.group(1)] = int(m.group(2).replace(",", ""))
        i += 1
    for method in ("nsloc", "heading_sloc", "cloc_code", "lines", "heading_count", "bullet_lines", "inline_loc"):
        if found.get(method):
            files = [{"name": k, "nsloc": v} for k, v in found[method].items()]
            return sum(f["nsloc"] for f in files), files, method
    m = re.search(r"total\s+n?sloc[^\n\d]{0,30}([\d,]{2,7})", readme, re.I)
    if m:
        return int(m.group(1).replace(",", "")), [], "total_line"
    return None, [], None


def fetch_code4rena(repo):
    meta = gh_api(f"repos/code-423n4/{repo}")
    commit = gh_api(f"repos/code-423n4/{repo}/commits/{meta['default_branch']}")["sha"]
    readme = base64.b64decode(gh_api(f"repos/code-423n4/{repo}/readme")["content"]).decode("utf-8", "replace")
    total, files, method = parse_sloc_tables(readme)
    return {
        "platform": "code4rena", "contest_id": repo, "title": repo, "nsloc": total, "nsloc_method": method,
        "repos": [{"repo": f"code-423n4/{repo}", "commit": commit, "nsloc": total}], "files": files,
        "languages": [meta.get("language")] if meta.get("language") else [],
        "readme": readme,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    ap.add_argument("--out", default="data/release/scope")
    ap.add_argument("--reparse", action="store_true", help="re-read cached Code4rena READMEs with the current parser; no network")
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    if args.reparse:
        for path in sorted(out.glob("code4rena-*.json")):
            if path.name.endswith(".error.json"):
                continue
            rec = json.loads(path.read_text())
            rec["nsloc"], rec["files"], rec["nsloc_method"] = parse_sloc_tables(rec["readme"])
            rec["repos"][0]["nsloc"] = rec["nsloc"]
            path.write_text(json.dumps(rec, indent=1))
        print("reparsed", flush=True)
        return
    c = duckdb.connect()
    c.execute(f"create view e as select * from read_csv_auto('{args.release}/engagements.csv', all_varchar=true)")
    c.execute(f"create view r as select * from read_csv_auto('{args.release}/reports.csv', all_varchar=true)")
    jobs = [("sherlock", eng, cid, fetch_sherlock) for eng, cid in sherlock_ids(c)]
    jobs += [("code4rena", eng, repo, fetch_code4rena) for eng, repo in code4rena_repos(c)]
    print(f"{len(jobs)} contests to look up", flush=True)
    ok = failed = cached = 0
    for n, (platform, eng, key, fn) in enumerate(jobs, 1):
        path = out / f"{platform}-{key}.json"
        if path.exists():
            cached += 1
            continue
        try:
            rec = fn(key)
            rec["engagement_id"] = eng
            ok += 1
        except Exception as exc:  # recorded and retried on the next run
            rec = {"platform": platform, "contest_id": key, "engagement_id": eng, "error": str(exc)[:300]}
            failed += 1
        if "error" not in rec:
            path.write_text(json.dumps(rec, indent=1))
        else:
            (out / f"{platform}-{key}.error.json").write_text(json.dumps(rec, indent=1))
        if n % 50 == 0:
            print(f"{n}/{len(jobs)} ok={ok} failed={failed} cached={cached}", flush=True)
        time.sleep(DELAY)
    print(f"done ok={ok} failed={failed} cached={cached}", flush=True)


if __name__ == "__main__":
    main()
