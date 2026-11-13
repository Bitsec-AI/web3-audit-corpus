"""Profile the starter-set audits listed in shortlist_56.txt and write datasets for the dashboard's Starter set tab.

Uses readiness.py's detectors (function names from the bug description only, PoC test, fix, attack path)
and the corpus root-cause labels. Measures how findings in the same audit overlap on function names and
whether overlapping findings get different root causes.

    .venv/bin/python -I benchmark-review/shortlist.py --release data/release --scope data/release/scope --out benchmark-review/datasets
"""
import argparse
import json
import re
import sys
from collections import Counter
from itertools import combinations
from pathlib import Path

import duckdb
import pandas as pd

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import readiness as R  # noqa: E402
ISSUE_LINK = re.compile(r"https://github\.com/(?:sherlock-audit|code-423n4)/[^\s)\]]+/issues/\d+")


def write(out, name, rows, meta):
    meta = meta + [
        {"label": "Audits", "value": "The 56 contests in shortlist_56.txt: under 2,000 nSLOC, 3+ critical/high/medium findings"},
        {"label": "shortlist.py", "value": Path(__file__).read_text(), "type": "code", "lang": "python"},
    ]
    (out / f"{name}.json").write_text(json.dumps({"rows": rows, "meta": meta}, separators=(",", ":"), default=str))


def bucket(n, edges):
    for label, lo, hi in edges:
        if lo <= n <= hi:
            return label
    return edges[-1][0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    ap.add_argument("--scope", default="data/release/scope")
    ap.add_argument("--out", default="benchmark-review/datasets")
    args = ap.parse_args()
    out = Path(args.out)
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
    scope_all = R.load_scope(args.scope)
    scope = scope_all[["engagement_id", "contest_key", "nsloc", "nsloc_method", "repo", "commit"]]
    df = R.apply_contest_names(df.merge(scope_all[["engagement_id", "contest_title", "contest_year"]], on="engagement_id", how="left"))

    df["functions"] = df.body_text.map(R.functions_in)
    df["n_functions"] = df.functions.map(len)
    df["poc"] = df.body_text.map(R.has_poc)
    df["fix"] = df.body_text.map(lambda b: R.has_diff(b) or bool(R.FIX_LINK.search(b)))
    df["attack"] = df.body_text.map(lambda b: bool(R.ATTACK_HEADING.search(b)))
    df["source_url"] = [m.group(0) if (m := ISSUE_LINK.search(b)) else u for b, u in zip(df.body_text, df.report_url)]

    # Overlap on function names within each audit.
    df["shares_with"] = 0
    df["shares_diff_root"] = 0
    pair_rows = []
    for eid, g in df.groupby("engagement_id"):
        recs = list(g[["finding_uid", "functions", "vuln_group", "vuln_leaf"]].itertuples(index=False))
        for a, b in combinations(recs, 2):
            common = set(a.functions) & set(b.functions)
            if common:
                diff = a.vuln_group != b.vuln_group
                pair_rows.append({"same_group": not diff, "same_leaf": a.vuln_leaf == b.vuln_leaf})
                for uid in (a.finding_uid, b.finding_uid):
                    df.loc[df.finding_uid == uid, "shares_with"] += 1
                    df.loc[df.finding_uid == uid, "shares_diff_root"] += int(diff)
    pairs = pd.DataFrame(pair_rows)

    # 1. Audits.
    aud = df.groupby("engagement_id").agg(
        project=("project", "first"), platform=("platform", "first"), audit_year=("audit_year", "first"),
        chm=("finding_uid", "size"), high=("severity", lambda s: int((s == "high").sum())),
        medium=("severity", lambda s: int((s == "medium").sum())), critical=("severity", lambda s: int((s == "critical").sum())),
        root_groups=("vuln_group", "nunique"), root_classes=("vuln_leaf", "nunique"),
        top_group=("vuln_group", lambda s: s.value_counts().index[0]),
        median_functions=("n_functions", "median"), no_function=("n_functions", lambda s: int((s == 0).sum())),
        with_poc=("poc", "sum"), with_fix=("fix", "sum"), sharing=("shares_with", lambda s: int((s > 0).sum())),
    ).reset_index().merge(scope, on="engagement_id", how="left")
    aud["every_finding_names_function"] = aud.no_function == 0
    aud["contest_url"] = [f"https://audits.sherlock.xyz/contests/{k}" if p == "sherlock" else f"https://code4rena.com/reports/{k}"
                          for p, k in zip(aud.platform, aud.contest_key)]
    aud["code_url"] = [f"https://github.com/{r}/tree/{c}" for r, c in zip(aud.repo, aud.commit)]
    aud = aud.sort_values("nsloc")
    write(out, "starter_audits", json.loads(aud.drop(columns=["repo"]).to_json(orient="records")),
          [{"label": "Rows", "value": "One per audit, smallest scope first"}])

    # 2. Findings.
    fcols = ["finding_uid", "engagement_id", "project", "platform", "finding_id", "title", "severity", "vuln_group", "vuln_leaf",
             "vuln_confidence", "n_functions", "functions", "shares_with", "shares_diff_root", "poc", "fix", "attack", "source_url"]
    frows = json.loads(df[fcols].assign(functions=df.functions.map(", ".join)).to_json(orient="records"))
    write(out, "starter_findings", frows, [{"label": "Functions", "value": "Named in the bug description, before any PoC test, mitigation or discussion"},
                                           {"label": "Root cause", "value": "Corpus label: one LLM-assigned class per finding"}])

    # 3. Root-cause groups by severity and platform.
    groups = []
    for grp, g in df.groupby("vuln_group"):
        groups.append({"vuln_group": grp, "findings": int(len(g)), "high": int((g.severity == "high").sum()),
                       "medium": int((g.severity == "medium").sum()), "critical": int((g.severity == "critical").sum()),
                       "sherlock": int((g.platform == "sherlock").sum()), "code4rena": int((g.platform == "code4rena").sum()),
                       "classes": int(g.vuln_leaf.nunique()), "audits": int(g.engagement_id.nunique())})
    groups.sort(key=lambda r: -r["findings"])
    write(out, "starter_root_causes", groups, [{"label": "Groups", "value": "Corpus root-cause groups (taxonomy.yaml)"}])

    # 4. Spread of function names per finding and classifier confidence.
    fn_edges = [("0", 0, 0), ("1", 1, 1), ("2", 2, 2), ("3", 3, 3), ("4–5", 4, 5), ("6–8", 6, 8), ("9+", 9, 10**6)]
    counts = Counter(bucket(n, fn_edges) for n in df.n_functions)
    write(out, "starter_function_spread", [{"functions": lab, "findings": int(counts.get(lab, 0))} for lab, _, _ in fn_edges],
          [{"label": "Count", "value": "Distinct function names per finding"}])
    conf_edges = [("<0.80", 0, 0.7999), ("0.80–0.85", 0.8, 0.8499), ("0.85–0.90", 0.85, 0.8999), ("0.90–0.95", 0.9, 0.9499), ("≥0.95", 0.95, 1.01)]
    ccounts = Counter(bucket(v, conf_edges) for v in df.vuln_confidence)
    write(out, "starter_confidence", [{"confidence": lab, "findings": int(ccounts.get(lab, 0))} for lab, _, _ in conf_edges],
          [{"label": "Confidence", "value": "The classifier's own uncalibrated score for its root-cause label"}])

    # 5. Summary row.
    summary = [{
        "audits": int(len(aud)), "findings": int(len(df)), "sherlock_audits": int((aud.platform == "sherlock").sum()),
        "code4rena_audits": int((aud.platform == "code4rena").sum()), "high": int((df.severity == "high").sum()),
        "medium": int((df.severity == "medium").sum()), "critical": int((df.severity == "critical").sum()),
        "strict_audits": int(aud.every_finding_names_function.sum()), "no_function_findings": int((df.n_functions == 0).sum()),
        "median_functions": float(df.n_functions.median()), "p90_functions": float(df.n_functions.quantile(0.9)),
        "max_functions": int(df.n_functions.max()), "pct_sharing": round(100 * (df.shares_with > 0).mean(), 1),
        "sharing_pairs": int(len(pairs)), "pairs_diff_group": int((~pairs.same_group).sum()) if len(pairs) else 0,
        "pct_pairs_diff_group": round(100 * (~pairs.same_group).mean(), 1) if len(pairs) else 0.0,
        "pairs_same_class": int(pairs.same_leaf.sum()) if len(pairs) else 0,
        "root_groups_used": int(df.vuln_group.nunique()), "root_classes_used": int(df.vuln_leaf.nunique()),
        "median_groups_per_audit": float(aud.root_groups.median()), "low_confidence": int((df.vuln_confidence < 0.85).sum()),
        "needs_review": int(df.vuln_needs_review.sum()), "unclassified": int((df.vuln_group == "unclassified").sum()),
        "with_poc": int(df.poc.sum()), "with_fix": int(df.fix.sum()), "with_attack": int(df.attack.sum()),
    }]
    write(out, "starter_summary", summary, [{"label": "Pairs", "value": "Two findings in the same audit that name at least one common function"}])
    print(json.dumps(summary[0], indent=1))
    print(pd.DataFrame(groups).to_string(index=False))


if __name__ == "__main__":
    main()
