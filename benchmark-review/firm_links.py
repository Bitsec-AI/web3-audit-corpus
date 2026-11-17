"""Review records with code locations and fix patches for OpenZeppelin, OtterSec, Zenith and Sherlock private reviews.

Audits per firm (at least 3 critical/high/medium findings) are screened in a shuffled order that alternates across
years, and the first --firms N audits whose code is public are kept (screened.json records every audit screened):
  1. Fetch the report: the OpenZeppelin HTML page, or the PDF (OtterSec, Zenith, Sherlock) read with
     `pdftohtml -xml` (poppler), which keeps each link next to its text.
  2. Split the report into findings by locating each corpus finding's title (the occurrence whose following text best
     matches the finding body, so the table of contents is skipped), and give each finding the links in its part.
  3. Scope commits: GitHub commit/tree/blob links before the first finding, and Sherlock's
     "Repository: ... Audited Commit: ..." lines. Each is checked on GitHub (with a public copy by commit search when
     the repo is private). Without a public audited commit, the base of the earliest public fix PR or the parent of a
     public fix commit stands in (the code just before the fixes). Source files are downloaded once (tarball).
  4. Locations per finding, in order of preference: links pinned to a commit with #L lines; Sherlock links into the
     sherlock-audit copy of the repo (mapped onto the audited commit); "file.ext#L10" text; otherwise the functions the
     text names, looked up in the audited code (method named_in_text).
  5. Functions and contracts at those lines come from the code (firm_code_data.enclosing).
  6. Fixes: pull request and commit links inside the finding (PRs preferred over commits of the same repo); diffs are
     saved with the Spearbit/Cantina patches.

    .venv/bin/python -I benchmark-review/firm_links.py --release data/release \
        --firms code4rena-zenith=30,sherlock=30,ottersec=30,openzeppelin=30
"""
import argparse
import html
import io
import json
import re
import subprocess
import sys
import tarfile
import time
import unicodedata
import urllib.parse
import urllib.request
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path

import duckdb

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import review_data  # noqa: E402
from fetch_report_links import COMMIT, PIN, PR, GitHub  # noqa: E402
from firm_code_data import FUNCTION, MAX_PATCH, blank, COMMENT, PY_COMMENT, CONTAINER, diff_stats, enclosing, gh_diff, spans  # noqa: E402

UA = "web3-audit-corpus-research (firm report links)"
SOURCE = re.compile(r"\.(sol|vy|rs|move|cairo|go|ts|js|nr|circom|cpp|hpp|cc|c|h|py)$")
VENDORED = re.compile(r"(^|/)(node_modules|lib|libs|vendor|dependencies|test|tests|mocks?|script|scripts|forge-std|\.github)/|\.t\.sol$|_test\.go$|\.spec\.ts$")
BRANCH_BLOB = re.compile(r"github\.com/(sherlock-audit/[\w.-]+)/blob/[\w.-]+/([^#?]+)(?:#L(\d+)(?:-L(\d+))?)?")
FILE_LINES = re.compile(r"([\w.-]+\.(?:sol|vy|rs|move|cairo|go|ts|nr|circom))#L(\d+)(?:-L?(\d+))?")
SCOPE_TEXT = [  # (repo, commit) pairs written out in scope sections
    re.compile(r"Repository:\s*([\w.-]+/[\w.-]+).{0,200}?Audited Commit:\s*([0-9a-f]{7,40})", re.S),  # Sherlock
    re.compile(r"Repository\s+https?://github\.com/([\w.-]+/[\w.-]+?)(?:\.git)?\s+Commit Hash\s+([0-9a-f]{7,40})"),  # Zenith
]
MAX_TARBALL = 300_000_000
CODE_OK = ("public", "public_copy", "pr_base", "fix_parent")
IDENT = re.compile(r"\b(_?[a-z][a-z0-9]*(?:_[a-z0-9]+)+|_?[a-z]+(?:[A-Z][a-z0-9]*)+)\b")  # snake_case or camelCase
STD_METHODS = {"as_ref", "as_bytes", "as_mut", "to_le_bytes", "to_be_bytes", "from_le_bytes", "try_from", "try_into", "checked_add",
               "checked_sub", "checked_mul", "checked_div", "saturating_sub", "saturating_add", "unwrap_or", "to_string", "to_vec",
               "into_iter", "is_some", "is_none", "is_empty", "borrow_mut", "safeTransfer", "safeTransferFrom", "transferFrom",
               "balanceOf", "totalSupply", "msg_sender", "block_timestamp", "mulDiv", "mulDivDown", "mulDivUp",
               "default", "new", "fmt", "clone", "from", "into", "drop", "deref", "eq", "hash", "len", "get", "set"}


def norm(text):
    return re.sub(r"[^a-z0-9]", "", unicodedata.normalize("NFKC", text).lower())


class Tokens(HTMLParser):
    """(text, href) pairs from an HTML page, skipping scripts and styles."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out, self.href, self.skip = [], [], 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "nav", "footer"):
            self.skip += 1
        if tag == "a":
            self.href.append(dict(attrs).get("href"))

    def handle_endtag(self, tag):
        if tag in ("script", "style", "nav", "footer"):
            self.skip = max(self.skip - 1, 0)
        if tag == "a" and self.href:
            self.href.pop()

    def handle_data(self, data):
        if not self.skip and data.strip():
            self.out.append((data, self.href[-1] if self.href else None))


def tokens(path):
    if path.suffix == ".html":
        p = Tokens()
        p.feed(path.read_text(errors="replace"))
        return p.out
    xml = subprocess.run(["pdftohtml", "-xml", "-i", "-q", "-stdout", str(path)], capture_output=True).stdout.decode(errors="replace")
    out = []
    for inner in re.findall(r"<text[^>]*>(.*?)</text>", xml, re.S):
        last = 0
        for m in re.finditer(r'<a href="([^"]*)">(.*?)</a>', inner, re.S):
            if m.start() > last:
                out.append((html.unescape(re.sub(r"<[^>]+>", "", inner[last:m.start()])), None))
            out.append((html.unescape(re.sub(r"<[^>]+>", "", m.group(2))), html.unescape(m.group(1))))
            last = m.end()
        if last < len(inner):
            out.append((html.unescape(re.sub(r"<[^>]+>", "", inner[last:])), None))
    return out


class Report:
    """A report as normalized text with the link positions and raw-text offsets needed to cut it into findings."""

    def __init__(self, toks):
        self.norm, self.raw, self.links, self.raw_at = "", "", [], []
        for text, href in toks:
            if href and href.startswith("http"):
                self.links.append((len(self.norm), href))
            self.raw_at.append((len(self.norm), len(self.raw)))
            self.norm += norm(text)
            self.raw += text + "\n"

    def raw_slice(self, a, b):
        to_raw = lambda n: next((r for nn, r in self.raw_at if nn >= n), len(self.raw))  # noqa: E731
        return self.raw[to_raw(a):to_raw(b)]

    def locate(self, title, body):
        """Start offset of the finding: the title occurrence followed by the most text of the body."""
        t, b = norm(title)[:60], norm(body)
        shingles = {b[i:i + 16] for i in range(len(t), len(b) - 16, max((len(b) - len(t)) // 40, 16))}
        starts = [m.start() for m in re.finditer(re.escape(t), self.norm)] if len(t) >= 12 else []
        if not starts and shingles:  # title not found: first matching piece of the body
            hits = sorted(p for s in shingles if (p := self.norm.find(s)) >= 0)
            return hits[0] if hits else None
        if not starts:
            return None
        score = lambda p: sum(s in self.norm[p:p + len(b) + 2000] for s in shingles)  # noqa: E731
        return max(starts, key=lambda p: (score(p), p))


def fetch(url, path):
    if path.exists():
        return path.stat().st_size > 1000
    m = re.match(r"https://github\.com/([^/]+/[^/]+)/blob/(.+)", url)
    u = f"https://raw.githubusercontent.com/{m.group(1)}/{m.group(2)}" if m else url
    try:
        req = urllib.request.Request(urllib.parse.quote(u, safe=":/%?=&#@"), headers={"User-Agent": UA})
        data = urllib.request.urlopen(req, timeout=90).read()
    except Exception as exc:
        print("fetch fail", url, exc, flush=True)
        data = b""
    time.sleep(1)
    path.write_bytes(data)
    return len(data) > 1000


def source_files(repo, full_sha, root):
    """Source files of repo at full_sha, extracted from the GitHub tarball into root (cached); {path: text}."""
    done = root / ".done"
    if not done.exists():
        root.mkdir(parents=True, exist_ok=True)
        try:
            req = urllib.request.Request(f"https://codeload.github.com/{repo}/tar.gz/{full_sha}", headers={"User-Agent": UA})
            data = urllib.request.urlopen(req, timeout=300).read(MAX_TARBALL)
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
                for member in tar:
                    parts = member.name.split("/")[1:]  # drop the <repo>-<sha>/ prefix
                    if not member.isfile() or member.size > 2_000_000 or not parts or ".." in parts or not SOURCE.search(member.name):
                        continue
                    dest = root.joinpath(*parts)
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(tar.extractfile(member).read())
        except Exception as exc:
            print("tarball fail", repo, full_sha, exc, flush=True)
        done.write_text("")
    return {str(p.relative_to(root)): p for p in root.rglob("*") if p.is_file() and SOURCE.search(p.name)}


def definitions(files):
    """name -> [(path, first line, last line, contract)] for functions defined outside tests and vendored code."""
    index = {}
    for path, p in files.items():
        if VENDORED.search(path):
            continue
        ext = path.rsplit(".", 1)[-1].lower()
        if ext not in FUNCTION:
            continue
        src = (PY_COMMENT if ext in ("py", "vy") else COMMENT).sub(blank, p.read_text(errors="replace"))
        boxes = spans(src, CONTAINER[ext], ext) if ext in CONTAINER else []
        for name, a, b, receiver in spans(src, FUNCTION[ext], ext):
            box = min((x for x in boxes if x[1] <= a <= x[2]), key=lambda x: x[2] - x[1], default=None)
            index.setdefault(name, []).append((path, a, b, receiver or (box[0] if box else None)))
    return index


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    ap.add_argument("--scope", default="data/release/scope")
    ap.add_argument("--firms", default="code4rena-zenith=30,sherlock=30,ottersec=30,openzeppelin=30",
                    help="firm=number of audits with public code to keep")
    ap.add_argument("--work", default="data/release/firm_links")
    ap.add_argument("--patches", default="data/release/report_links/patches")
    ap.add_argument("--out", default=str(HERE / "review" / "firm_others.json"))
    args = ap.parse_args()
    work, patch_dir = Path(args.work), Path(args.patches)
    for d in ("reports", "code", "trees"):
        (work / d).mkdir(parents=True, exist_ok=True)
    patch_dir.mkdir(parents=True, exist_ok=True)
    gh = GitHub(work / "github.json", work / "trees")

    targets = {k: int(v) for k, v in (x.split("=") for x in args.firms.split(","))}
    # 1. candidate audits: primary report in the firm's usual format, at least 3 critical/high/medium findings
    c = duckdb.connect()
    c.execute(f"create view e as select * from read_csv_auto('{args.release}/engagements.csv', all_varchar=true)")
    c.execute(f"create view r as select * from read_csv_auto('{args.release}/reports.csv', all_varchar=true)")
    cand = c.execute(f"""select e.engagement_id, e.firm_id, e.project, try_cast(e.audit_year as int) yr, r.report_id, r.url
        from e join r on r.report_id = e.primary_report_id
        where e.firm_id in (select unnest(?)) and e.review_mode = 'firm_review'
          and (r.url like 'https://www.openzeppelin.com/news/%' or r.url like 'https://osec.io/reports/%'
               or (e.firm_id in ('code4rena-zenith', 'sherlock') and lower(r.url) like '%.pdf'))
          and (select count(*) from '{args.release}/findings.parquet' f where f.engagement_id = e.engagement_id and f.selected_for_stats
               and f.severity in ('critical', 'high', 'medium') and f.body_text_status = 'present') >= 3""", [list(targets)]).df()
    # screening order per firm: shuffled, alternating across years so the kept audits spread over years
    order = {}
    for firm in targets:
        g = cand[cand.firm_id == firm].sample(frac=1, random_state=13)
        by_year = [list(x.itertuples()) for _, x in g.groupby("yr")]
        order[firm], i = [], 0
        while any(by_year):
            if by_year[i % len(by_year)]:
                order[firm].append(by_year[i % len(by_year)].pop())
            i += 1

    findings = c.execute(f"""select finding_uid, engagement_id, title, severity, body_text from '{args.release}/findings.parquet'
        where selected_for_stats and engagement_id in (select unnest(?))""", [list(cand.engagement_id)]).fetchall()
    by_eng = {}
    for uid, eid, title, sev, body in findings:
        by_eng.setdefault(eid, []).append({"uid": uid, "title": title or "", "severity": sev, "body": body or ""})

    audits, per_finding, screened = {}, {}, {}

    def screen(a):
        """Fetch the report, split it into findings and find the audited code; returns the audit record."""
        ext = ".html" if "openzeppelin.com/news" in a.url else ".pdf"
        path = work / "reports" / f"{a.report_id.split(':')[-1][:16]}{ext}"
        rec = {"engagement_id": a.engagement_id, "firm": a.firm_id, "project": a.project, "year": int(a.yr), "report": a.url,
               "fetched": fetch(a.url, path)}
        if not rec["fetched"]:
            return rec
        rep = Report(tokens(path))
        # 2. findings -> report parts
        fs = by_eng[a.engagement_id]
        starts = sorted((p, i) for i, f in enumerate(fs) if (p := rep.locate(f["title"], f["body"])) is not None)
        first = starts[0][0] if starts else len(rep.norm)
        for k, (p, i) in enumerate(starts):
            end = starts[k + 1][0] if k + 1 < len(starts) else p + int(len(norm(fs[i]["body"])) * 1.3) + 500
            per_finding[fs[i]["uid"]] = {"links": [h for pos, h in rep.links if p <= pos < end], "text": rep.raw_slice(p, end)}
        rec["findings_located_in_report"] = len(starts)
        # 3. scope commits
        pre = [h for pos, h in rep.links if pos < first]
        written = list(dict.fromkeys((r.lower(), s) for pat in SCOPE_TEXT for r, s in pat.findall(rep.raw_slice(0, first))))
        linked = list(dict.fromkeys((m.group(1).lower().removesuffix(".git"), m.group(2)) for h in pre if (m := PIN.search(h) or COMMIT.search(h))))
        if not written and not linked:  # no scope section: the most-linked pinned commit in the findings
            pins = Counter((m.group(1).lower().removesuffix(".git"), m.group(2)) for _, h in rep.links if (m := PIN.search(h)))
            linked = [k for k, _ in pins.most_common(1)]
        # links before the findings can be references (a forked protocol, a dependency): when the findings' fix links
        # all name other repos, those links are not the scope. A written scope section is kept as it is.
        parts = [per_finding[f["uid"]] for f in fs if f["uid"] in per_finding]
        own = Counter(m.group(1).lower().removesuffix(".git") for part in parts for h in part["links"]
                      if (m := PR.search(h) or COMMIT.search(h)) and not m.group(1).lower().startswith("sherlock-audit/"))
        if not written and own and not any(repo in own for repo, _ in linked):
            rec["reference_links"] = [f"{r}@{s}" for r, s in linked]
            linked = []
        scope = list(dict.fromkeys(written + linked))
        rec["scope"] = []
        for repo, sha in scope[:4]:
            status, full = gh.commit(repo, sha)
            fetch_repo = repo
            if status != "public":
                copies = gh.copies(sha)
                if copies:
                    st, f2 = gh.commit(copies[0].lower(), sha)
                    if st == "public":
                        status, full, fetch_repo = "public_copy", f2, copies[0].lower()
            rec["scope"].append({"repo": repo, "sha": sha, "status": status, "full_sha": full, "fetch_repo": fetch_repo})
        if not any(x["status"] in CODE_OK for x in rec["scope"]):
            # no public audited commit: the base of the earliest public fix PR is the code just before the fixes
            prs = sorted({(m.group(1).lower(), int(m.group(2))) for part in parts for h in part["links"] if (m := PR.search(h))},
                         key=lambda x: (-own[x[0]], x[1]))
            for repo, n in prs[:3]:
                key = f"prbase:{repo}#{n}"
                if key not in gh.cache:
                    res = gh.api(f"repos/{repo}/pulls/{n}", ".base.sha")
                    gh.cache[key] = res.stdout.strip() if res.returncode == 0 else None
                if gh.cache[key]:
                    base = gh.cache[key]
                    rec["scope"].append({"repo": repo, "sha": base, "status": "pr_base", "full_sha": base, "fetch_repo": repo, "pr": n})
                    break
        if not any(x["status"] in CODE_OK for x in rec["scope"]):
            # or the parent of the first public fix commit
            fix_commits = list(dict.fromkeys((m.group(1).lower(), m.group(2)) for part in parts for h in part["links"] if (m := COMMIT.search(h))))
            for repo, sha in sorted(fix_commits, key=lambda x: -own[x[0]])[:3]:
                key = f"parent:{repo}@{sha}"
                if key not in gh.cache:
                    res = gh.api(f"repos/{repo}/commits/{sha}", ".parents[0].sha")
                    gh.cache[key] = res.stdout.strip() if res.returncode == 0 and res.stdout.strip() else None
                if gh.cache[key]:
                    parent = gh.cache[key]
                    rec["scope"].append({"repo": repo, "sha": parent, "status": "fix_parent", "full_sha": parent, "fetch_repo": repo, "fix_commit": sha})
                    break
        gh.save()
        print(f"{a.firm_id:17} {a.yr} {a.project[:40]:40} findings {len(starts)}/{len(fs)} scope "
              f"{[(s['repo'], s['sha'][:7], s['status']) for s in rec['scope']]}", flush=True)
        return rec

    for firm, target in targets.items():
        kept = 0
        for a in order[firm]:
            if kept >= target:
                break
            rec = screen(a)
            screened.setdefault(firm, []).append({k: rec.get(k) for k in ("engagement_id", "project", "year", "fetched", "scope", "reference_links")})
            if any(x["status"] in CODE_OK for x in rec.get("scope", [])):
                audits[a.engagement_id] = rec
                kept += 1
        print(f"== {firm}: kept {kept} audits with public code of {len(screened[firm])} screened ({len(order[firm])} candidates)", flush=True)

    # 4-5. code, locations and functions
    code = {}
    for rec in audits.values():
        for s in rec.get("scope", []):
            if s["status"] in CODE_OK and (s["fetch_repo"], s["full_sha"]) not in code:
                files = source_files(s["fetch_repo"], s["full_sha"], work / "code" / f"{s['fetch_repo'].replace('/', '__')}@{s['full_sha'][:12]}")
                code[(s["fetch_repo"], s["full_sha"])] = (files, definitions(files))
    raw_cache = work / "code" / "_files"

    def file_text(repo, sha, path):
        """Text of a file at a pinned commit: from a downloaded scope tree, else fetched from GitHub."""
        for s in next((r["scope"] for r in audits.values() if any(x["repo"] == repo and x["sha"] == sha for x in r.get("scope", []))), []):
            if s["repo"] == repo and s["sha"] == sha and (s["fetch_repo"], s["full_sha"]) in code:
                p = code[(s["fetch_repo"], s["full_sha"])][0].get(path)
                return p.read_text(errors="replace") if p else None
        status, full = gh.commit(repo, sha)
        if status != "public":
            return None
        dest = raw_cache / f"{repo.replace('/', '__')}@{full[:12]}" / path
        if not dest.exists():
            dest.parent.mkdir(parents=True, exist_ok=True)
            fetch(f"https://raw.githubusercontent.com/{repo}/{full}/{path}", dest)
        return dest.read_text(errors="replace") if dest.stat().st_size else None

    def locate_finding(rec, f, functions_text):
        part = per_finding.get(f["uid"])
        scopes = [s for s in rec.get("scope", []) if (s["fetch_repo"], s["full_sha"]) in code]
        locs = []
        if part:
            for h in part["links"]:
                if (m := PIN.search(h)) and m.group(3) and SOURCE.search(m.group(3)):
                    repo, sha, path, a, b = m.group(1).lower().removesuffix(".git"), m.group(2), urllib.parse.unquote(m.group(3)), m.group(4), m.group(5)
                    locs.append({"repo": repo, "sha": sha, "path": path, "start": int(a) if a else None, "end": int(b or a) if a else None, "method": "link"})
                elif (m := BRANCH_BLOB.search(h)) and SOURCE.search(m.group(2)) and scopes:
                    parts = urllib.parse.unquote(m.group(2)).split("/")
                    s = scopes[0]
                    files = code[(s["fetch_repo"], s["full_sha"])][0]
                    path = next(("/".join(parts[i:]) for i in range(len(parts)) if "/".join(parts[i:]) in files), None)
                    if path:
                        a, b = m.group(3), m.group(4)
                        locs.append({"repo": s["repo"], "sha": s["sha"], "path": path, "start": int(a) if a else None,
                                     "end": int(b or a) if a else None, "method": "audit_repo_link"})
            if not locs and scopes:
                s = scopes[0]
                files = code[(s["fetch_repo"], s["full_sha"])][0]
                for name, a, b in FILE_LINES.findall(part["text"]):
                    hits = [p for p in files if p.split("/")[-1] == name and not VENDORED.search(p)]
                    if len(hits) == 1:
                        locs.append({"repo": s["repo"], "sha": s["sha"], "path": hits[0], "start": int(a), "end": int(b or a), "method": "file_lines"})
        # same file and lines once
        locs = list({(l["path"], l["start"], l["end"]): l for l in locs}.values())
        if not locs and scopes:
            s = scopes[0]
            index = code[(s["fetch_repo"], s["full_sha"])][1]
            mentioned = {m.split("/")[-1] for m in re.findall(r"[\w/.-]+\.(?:sol|rs|move|go|vy|cairo|ts)\b", f["body"])}
            # functions the text names, then other identifiers in the text that the code defines (PDF text loses backticks)
            idents = Counter(IDENT.findall(f["body"]))
            names = [n for n in list(dict.fromkeys(functions_text)) + [n for n, _ in idents.most_common()]
                     if n in index and n not in STD_METHODS]
            for name in list(dict.fromkeys(names))[:3]:
                defs = index.get(name, [])
                if len(defs) > 1 and mentioned:
                    defs = [d for d in defs if d[0].split("/")[-1] in mentioned] or defs
                if len(defs) > 1 and name not in functions_text:
                    continue  # an identifier the text does not call a function, defined in several places: too weak
                for path, a, b, _ in defs[:2]:
                    locs.append({"repo": s["repo"], "sha": s["sha"], "path": path, "start": a, "end": a, "method": "named_in_text",
                                 "ambiguous": len(defs) > 1})
        for l in locs:
            text = file_text(l["repo"], l["sha"], l["path"])
            l["code"] = "fetched" if text else "unavailable"
            l["functions"], l["contract"] = enclosing(text, l["path"], l["start"], l["end"]) if text else ([], None)
            s = next((x for x in rec.get("scope", []) if x["repo"] == l["repo"] and x["sha"] == l["sha"]), None)
            fetch_repo, full = (s["fetch_repo"], s["full_sha"]) if s else (l["repo"], gh.commit(l["repo"], l["sha"])[1] or l["sha"])
            lines = (f"#L{l['start']}" + (f"-L{l['end']}" if l["end"] and l["end"] != l["start"] else "")) if l["start"] else ""
            l["url"] = f"https://github.com/{fetch_repo}/blob/{full}/{l['path']}{lines}"
        return locs

    # 6. fixes
    def fixes_for(rec, f):
        part = per_finding.get(f["uid"])
        if not part:
            return []
        scope_shas = {s["sha"] for s in rec.get("scope", [])}
        prs = list(dict.fromkeys((m.group(1).lower(), m.group(2)) for h in part["links"] if (m := PR.search(h))))
        commits = list(dict.fromkeys((m.group(1).lower(), m.group(2)) for h in part["links"] if (m := COMMIT.search(h)) and m.group(2) not in scope_shas))
        pr_repos = {r for r, _ in prs}
        refs = [("pull", r, n) for r, n in prs] + [("commit", r, h) for r, h in commits if r not in pr_repos]
        out = []
        for kind, repo, ref in refs:
            name = f"{repo.replace('/', '__')}__{kind}_{ref}.diff"
            status = gh_diff(f"repos/{repo}/{'pulls' if kind == 'pull' else 'commits'}/{ref}", patch_dir / name)
            if status == "ok" and (patch_dir / name).stat().st_size > MAX_PATCH:
                status = "too_large"
            x = {"kind": kind, "repo": repo, "ref": ref, "inferred_repo": False, "status": status, "url": f"https://github.com/{repo}/{kind}/{ref}"}
            if status == "ok":
                x.update(diff_stats((patch_dir / name).read_text(errors="replace")), patch=f"patches/{name}")
            out.append(x)
        return out

    def overlay(records):
        for rec in records:
            audit = audits[rec["engagement_id"]]
            rec["functions_text"] = rec["functions"]
            f = {"uid": rec["uid"], "body": rec["body"] or ""}
            locs = locate_finding(audit, f, rec["functions"])
            pairs, contracts, files = [], [], {}
            for l in locs:
                for p in l["functions"]:
                    if p["function"] not in [q["function"] for q in pairs]:
                        pairs.append({"function": p["function"], "contract": p["contract"]})
                contracts += [p["contract"] for p in l["functions"] if p["contract"]] + ([l["contract"]] if l["contract"] else [])
                name = l["path"].split("/")[-1]
                files.setdefault(name, {"name": name, "path": l["path"], "how": "code" if l["code"] == "fetched" else "mention", "external": False, "in_scope": None})
            if locs:
                rec["files"], rec["fn_contract"] = list(files.values()), pairs
                rec["functions"] = [p["function"] for p in pairs]
                rec["contracts"] = list(dict.fromkeys(contracts))
            rec["locations"] = locs
            rec["in_report"] = rec["uid"] in per_finding
            s = next((x for x in audit.get("scope", []) if x["status"] in CODE_OK), None)
            rec["code_url"] = f"https://github.com/{s['fetch_repo']}/tree/{s['full_sha']}" if s else None
            rec["source_url"] = audit["report"]
            rec["fixes"] = fixes_for(audit, f)
            rec["fix"] = rec["fix"] or any(x["status"] == "ok" for x in rec["fixes"])
            names = {l["path"].split("/")[-1] for l in locs}
            for x in rec["fixes"]:
                if x["status"] == "ok":
                    x["touches_finding_file"] = any(p.split("/")[-1] in names for p in x["files"])

    records = review_data.build(args.release, args.scope, list(audits), overlay=overlay)
    for rec in records:
        if not rec["in_report"]:
            rec["flags"].append("not found in the report")
        if not rec["code_url"]:
            rec["flags"].append("audited code not public")
        elif not any(x["status"] in ("public", "public_copy") for x in audits[rec["engagement_id"]].get("scope", [])):
            rec["flags"].append("code from just before a fix (PR base or fix commit parent)")
        if any(l["method"] == "named_in_text" for l in rec["locations"]):
            rec["flags"].append("location from a function named in the text")
        if any(l.get("ambiguous") for l in rec["locations"]):
            rec["flags"].append("function defined in several files")
        if rec["locations"] and any(l["code"] == "fetched" and not l["functions"] and l["start"] for l in rec["locations"]):
            rec["flags"].append("a location is outside any function")
        if not any(x["status"] == "ok" for x in rec["fixes"]):
            rec["flags"].append("no fix patch")
        elif not any(x.get("touches_finding_file") for x in rec["fixes"]):
            rec["flags"].append("patch misses the finding's files")
    gh.save()
    (work / "audits.json").write_text(json.dumps(list(audits.values()), indent=1))
    (work / "screened.json").write_text(json.dumps(screened, indent=1))
    review_data.write(records, args.out)

    print("\nper firm: audits | code public | findings | in report | located | function from code (lines) | named_in_text only | fix ref | patch | patch touches file")
    for firm in targets:
        rs = [r for r in records if r["platform"] == firm]
        au = [a for a in audits.values() if a["firm"] == firm]
        line_fn = lambda r: any(l["functions"] and l["method"] != "named_in_text" for l in r["locations"])  # noqa: E731
        print(f"{firm:17} {len(au):3} | {sum(any(s['status'] in CODE_OK for s in a.get('scope', [])) for a in au):3} | "
              f"{len(rs):4} | {sum(r['in_report'] for r in rs):4} | {sum(bool(r['locations']) for r in rs):4} | {sum(line_fn(r) for r in rs):4} | "
              f"{sum(bool(r['locations']) and all(l['method'] == 'named_in_text' for l in r['locations']) for r in rs):4} | "
              f"{sum(bool(r['fixes']) for r in rs):4} | {sum(any(x['status'] == 'ok' for x in r['fixes']) for r in rs):4} | "
              f"{sum(any(x.get('touches_finding_file') for x in r['fixes']) for r in rs):4}")


if __name__ == "__main__":
    main()
