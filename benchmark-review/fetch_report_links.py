"""Recover audited code locations for Spearbit and Cantina audits from the links embedded in their report PDFs.

For every Spearbit/Cantina report PDF:
  1. Download it (4 workers, one request per second each; cached under --out/pdfs, reruns skip cached files).
  2. Extract the link targets (/URI entries, including those inside compressed streams), in order of appearance.
  3. Classify GitHub links: pinned blob/tree links (repo + commit [+ path + #L lines]), pull requests, commits.
  4. Check each pinned commit with the GitHub API (public / repo missing or private / commit missing). A scope commit
     (the commit with the most pinned links) that is not public is searched by hash, since forks keep commit hashes:
     a public copy, often someone's fork of a cantina-forks repo, gives status public_copy. List the file tree of the
     scope commit and of other audited repos (at least half as many links as the scope repo).
  5. Resolve each finding's "Context: File.sol#L10-L20" entries to repo + commit + path + lines: first against the
     report's own pinned links, then by unique file name in the scope commit's tree.

GitHub responses are cached in --out/github.json and --out/trees/.

Outputs in --out:
  engagements.json  one record per audit: repos, scope commit and its status, PR and fix-commit links, counts
  findings.json     one record per finding: Context entries and their resolved code locations
                    (hcm_located counts critical/high/medium findings whose every Context entry resolves to a public commit)

    .venv/bin/python -I benchmark-review/fetch_report_links.py --release data/release --out data/release/report_links
"""
import argparse
import json
import re
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import zlib
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import duckdb

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from firm_sample import cantina_republications  # noqa: E402

UA = "web3-audit-corpus-research (report links)"
DELAY = 1.0
PIN = re.compile(r"github\.com/([\w.-]+/[\w.-]+?)/+(?:blob|tree)/([0-9a-f]{7,40})(?:/([^#?]*))?(?:#L(\d+)(?:-L(\d+))?)?")
PR = re.compile(r"github\.com/([\w.-]+/[\w.-]+?)/pull/(\d+)")
COMMIT = re.compile(r"github\.com/([\w.-]+/[\w.-]+?)/commit/([0-9a-f]{7,40})")
CONTEXT = re.compile(r"Context:\s*([^\n]+)")
CONTEXT_ITEM = re.compile(r"(?:[\w.-]+::)?([\w./-]+\.\w+)(?:#L(\d+)(?:-L(\d+))?)?")


def fetch(url, path):
    if path.exists() and path.stat().st_size > 1000:
        return True
    m = re.match(r"https://github\.com/([^/]+/[^/]+)/blob/(.+)", url)
    u = f"https://raw.githubusercontent.com/{m.group(1)}/{m.group(2)}" if m else url
    try:
        req = urllib.request.Request(urllib.parse.quote(u, safe=":/%?=&#"), headers={"User-Agent": UA})
        data = urllib.request.urlopen(req, timeout=90).read()
        if not data.startswith(b"%PDF"):
            print("not a pdf", url, flush=True)
            return False
        path.write_bytes(data)
        return True
    except Exception as exc:
        print("fetch fail", url, exc, flush=True)
        return False
    finally:
        time.sleep(DELAY)


def pdf_links(pdf):
    """Link targets in order of first appearance."""
    data = pdf.read_bytes()
    chunks = [data]
    for m in re.finditer(rb"stream\r?\n", data):
        end = data.find(b"endstream", m.end())
        try:
            chunks.append(zlib.decompress(data[m.end():end]))
        except Exception:
            pass
    seen = {}
    for ch in chunks:
        for u in re.findall(rb"/URI\s*\(((?:[^)\\]|\\.)*)\)", ch):
            seen.setdefault(u.decode("latin1").replace("\\/", "/").replace("\\\\", "\\"), None)
    return list(seen)


class GitHub:
    """gh api with a JSON cache and a wait when the rate limit runs out."""

    def __init__(self, cache_path, tree_dir):
        self.path, self.tree_dir = cache_path, tree_dir
        self.cache = json.loads(cache_path.read_text()) if cache_path.exists() else {}
        tree_dir.mkdir(exist_ok=True)

    def api(self, endpoint, jq):
        while True:
            res = subprocess.run(["gh", "api", endpoint, "--jq", jq], capture_output=True, text=True)
            if "rate limit" in res.stderr.lower() and endpoint.startswith("search/"):
                print("search rate limited; waiting 61s", flush=True)
                time.sleep(61)
                continue
            if "rate limit" in res.stderr.lower():
                reset = int(subprocess.run(["gh", "api", "rate_limit", "--jq", ".resources.core.reset"],
                                           capture_output=True, text=True).stdout or time.time() + 600)
                print(f"rate limited; waiting {reset - time.time():.0f}s", flush=True)
                time.sleep(max(reset - time.time(), 0) + 5)
                continue
            time.sleep(0.2)
            return res

    def save(self):
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.cache))
        tmp.replace(self.path)

    def repo(self, repo):
        key = f"repo:{repo}"
        if key not in self.cache:
            res = self.api(f"repos/{repo}", ".full_name")
            self.cache[key] = res.stdout.strip() if res.returncode == 0 else None
        return self.cache[key]

    def commit(self, repo, sha):
        """('public', full sha) | ('repo_public_commit_missing', None) | ('repo_missing_or_private', None)."""
        key = f"commit:{repo}@{sha}"
        if key not in self.cache:
            if self.repo(repo) is None:
                self.cache[key] = ["repo_missing_or_private", None]
            else:
                res = self.api(f"repos/{repo}/commits/{sha}", ".sha")
                self.cache[key] = ["public", res.stdout.strip()] if res.returncode == 0 else ["repo_public_commit_missing", None]
        return tuple(self.cache[key])

    def copies(self, sha):
        """Public repos that contain this commit, found by GitHub commit search (30 searches a minute)."""
        key = f"search:{sha}"
        if key not in self.cache:
            res = self.api(f"search/commits?q=hash:{sha}", "[.items[].repository.full_name]")
            time.sleep(2)
            self.cache[key] = json.loads(res.stdout) if res.returncode == 0 else None
        return self.cache[key] or []

    def tree(self, repo, full_sha):
        """File paths at a commit (None if the tree is unavailable); truncated trees keep what GitHub returned."""
        path = self.tree_dir / f"{repo.replace('/', '__')}@{full_sha}.json"
        if not path.exists():
            res = self.api(f"repos/{repo}/git/trees/{full_sha}?recursive=1",
                           '{truncated: .truncated, paths: [.tree[] | select(.type == "blob") | .path]}')
            path.write_text(res.stdout if res.returncode == 0 else "null")
        return json.loads(path.read_text())


def context_items(body):
    m = CONTEXT.search(body or "")
    if not m:
        return []
    return [{"file": f.split("/")[-1], "start": int(a) if a else None, "end": int(b) if b else (int(a) if a else None)}
            for f, a, b in CONTEXT_ITEM.findall(m.group(1))]


def resolve(item, pins, trees):
    """Code location for one Context entry: a pinned link with the same file and lines, a pinned link to the same file,
    or the only file of that name in the scope commit's tree."""
    same_file = [p for p in pins if p["path"] and p["path"].split("/")[-1] == item["file"]]
    exact = [p for p in same_file if p["start"] == item["start"]]
    for method, cands in (("link_lines", exact), ("link_file", same_file)):
        if len({(p["repo"], p["sha"], p["path"]) for p in cands}) == 1:
            p = cands[0]
            return {"repo": p["repo"], "sha": p["sha"], "path": p["path"], "start": item["start"], "end": item["end"], "method": method}
    hits = [(repo, sha, path) for (repo, sha), paths in trees.items() for path in paths if path.split("/")[-1] == item["file"]]
    if len(hits) == 1:
        repo, sha, path = hits[0]
        return {"repo": repo, "sha": sha, "path": path, "start": item["start"], "end": item["end"], "method": "tree"}
    return {"file": item["file"], "start": item["start"], "end": item["end"], "method": "ambiguous" if hits else None,
            "candidates": len(hits)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    ap.add_argument("--out", default="data/release/report_links")
    ap.add_argument("--workers", type=int, default=4)
    args = ap.parse_args()
    out = Path(args.out)
    (out / "pdfs").mkdir(parents=True, exist_ok=True)

    c = duckdb.connect()
    c.execute(f"create view e as select * from read_csv_auto('{args.release}/engagements.csv', all_varchar=true)")
    c.execute(f"create view r as select * from read_csv_auto('{args.release}/reports.csv', all_varchar=true)")
    reports = c.execute("""select r.report_id, r.engagement_id, r.firm_id, r.url, e.project, e.review_mode, e.audit_year
        from r join e using(engagement_id) where r.firm_id in ('spearbit', 'cantina') and lower(r.url) like '%.pdf'
        order by r.report_id""").fetchall()
    findings = c.execute(f"""select finding_uid, engagement_id, report_id, severity, title, body_text
        from '{args.release}/findings.parquet' where selected_for_stats and firm_id in ('spearbit', 'cantina')""").fetchall()
    republished = cantina_republications(c, args.release)

    # 1-2. download and extract
    pdf_of = {rid: out / "pdfs" / f"{rid.split(':')[-1][:16]}.pdf" for rid, *_ in reports}
    done = [0]
    lock = threading.Lock()

    def work(rep):
        ok = fetch(rep[3], pdf_of[rep[0]])
        with lock:
            done[0] += 1
            if done[0] % 50 == 0:
                print(f"fetched {done[0]}/{len(reports)}", flush=True)
        return rep[0], ok

    with ThreadPoolExecutor(args.workers) as pool:
        fetched = dict(pool.map(work, reports))
    links = {rid: pdf_links(pdf_of[rid]) if fetched[rid] else [] for rid, *_ in reports}
    print(f"fetched {sum(fetched.values())}/{len(reports)} PDFs", flush=True)

    # 3. classify links per engagement
    eng = {}
    for rid, eid, firm, url, project, mode, year in reports:
        rec = eng.setdefault(eid, {"engagement_id": eid, "firm": firm, "mode": mode, "year": year, "project": project,
                                   "republishes_spearbit": eid in republished, "reports": [], "pins": [], "prs": [],
                                   "fix_commits": [], "links": 0})
        rec["reports"].append({"report_id": rid, "url": url, "fetched": fetched[rid]})
        rec["links"] += len(links[rid])
        for u in links[rid]:
            if m := PIN.search(u):
                repo, sha, path, a, b = m.groups()
                rec["pins"].append({"report_id": rid, "repo": repo.lower(), "sha": sha, "path": urllib.parse.unquote(path or "") or None,
                                    "start": int(a) if a else None, "end": int(b) if b else None})
            elif m := PR.search(u):
                rec["prs"].append(f"{m.group(1).lower()}#{m.group(2)}")
            elif m := COMMIT.search(u):
                rec["fix_commits"].append(f"{m.group(1).lower()}@{m.group(2)}")
    for rec in eng.values():
        rec["prs"] = sorted(set(rec["prs"]))
        rec["fix_commits"] = sorted(set(rec["fix_commits"]))

    # 4. GitHub checks
    gh = GitHub(out / "github.json", out / "trees")
    commits = sorted({(p["repo"], p["sha"]) for rec in eng.values() for p in rec["pins"]})
    print(f"checking {len(commits)} pinned commits in {len({r for r, _ in commits})} repos", flush=True)
    for i, (repo, sha) in enumerate(commits, 1):
        gh.commit(repo, sha)
        if i % 100 == 0:
            gh.save()
            print(f"checked {i}/{len(commits)}", flush=True)
    gh.save()
    trees_of = {}
    for n_eng, rec in enumerate(eng.values(), 1):
        counts = Counter((p["repo"], p["sha"]) for p in rec["pins"])
        status = {k: gh.commit(*k) for k in counts}
        rec["commits"] = [{"repo": r, "sha": s, "links": n, "status": status[(r, s)][0], "full_sha": status[(r, s)][1]}
                          for (r, s), n in counts.most_common()]
        repo_links = Counter()
        for x in rec["commits"]:
            repo_links[x["repo"]] += x["links"]
        rec["repos"] = [r for r, _ in repo_links.most_common()]
        # audited repos: the scope commit's repo and any repo with at least half its links; the rest are references
        audited = {r for r, n in repo_links.items() if rec["commits"] and n * 2 >= repo_links[rec["commits"][0]["repo"]]}
        rec["audited_repos"] = sorted(audited, key=lambda r: -repo_links[r])
        rec["scope_commit"] = rec["commits"][0] if rec["commits"] else None
        trees = {}
        for x in rec["commits"]:
            if x["repo"] not in audited or x["repo"] in {r for r, _ in trees}:
                continue
            if x["status"] != "public":
                if x is not rec["scope_commit"]:
                    continue
                copies = gh.copies(x["sha"])
                if not copies:
                    continue
                name = x["repo"].split("/")[1]
                copy = next((cp for cp in copies if cp.lower().split("/")[1] == name), copies[0]).lower()
                st, full = gh.commit(copy, x["sha"])
                if st != "public":
                    continue
                x.update(status="public_copy", copy_repo=copy, full_sha=full)
            t = gh.tree(x.get("copy_repo", x["repo"]), x["full_sha"])
            if t:
                trees[(x["repo"], x["sha"])] = t["paths"]
        trees_of[rec["engagement_id"]] = trees
        if n_eng % 50 == 0:
            gh.save()
    gh.save()

    # 5. resolve Context entries per finding
    rows = []
    for uid, eid, rid, sev, title, body in findings:
        if eid not in eng:
            continue
        pins = [p for p in eng[eid]["pins"] if p["report_id"] == rid] or eng[eid]["pins"]
        items = context_items(body)
        locations = [resolve(it, pins, trees_of[eid]) for it in items]
        copy_of = {(x["repo"], x["sha"]): x["copy_repo"] for x in eng[eid]["commits"] if x.get("copy_repo")}
        for loc in locations:
            if (loc.get("repo"), loc.get("sha")) in copy_of:
                loc["copy_repo"] = copy_of[(loc["repo"], loc["sha"])]  # where the private commit can be fetched
        rows.append({"finding_uid": uid, "engagement_id": eid, "severity": sev, "title": title,
                     "context": items, "locations": locations})
    by_eng = {}
    for row in rows:
        by_eng.setdefault(row["engagement_id"], []).append(row)
    for eid, rec in eng.items():
        fs = by_eng.get(eid, [])
        hcm = [f for f in fs if f["severity"] in ("critical", "high", "medium")]
        fetchable = {(x["repo"], x["sha"]) for x in rec["commits"] if x["status"] in ("public", "public_copy")}
        located = lambda f: f["locations"] and all((loc.get("repo"), loc.get("sha")) in fetchable for loc in f["locations"])  # noqa: E731
        rec.update(findings=len(fs), hcm=len(hcm), hcm_with_context=sum(bool(f["context"]) for f in hcm),
                   hcm_located=sum(bool(located(f)) for f in hcm),
                   code_available=bool(rec["scope_commit"]) and rec["scope_commit"]["status"] in ("public", "public_copy"),
                   scope_status=rec["scope_commit"]["status"] if rec["scope_commit"] else None,
                   pinned_files=len({(p["repo"], p["sha"], p["path"]) for p in rec["pins"] if p["path"] and "." in p["path"]}))
        rec["pins"] = len(rec["pins"])

    (out / "engagements.json").write_text(json.dumps(sorted(eng.values(), key=lambda r: (r["firm"], r["mode"], r["year"] or "")), indent=1))
    (out / "findings.json").write_text(json.dumps(rows, indent=1))
    print(f"DONE {len(eng)} engagements, {len(rows)} findings -> {out}", flush=True)


if __name__ == "__main__":
    main()
