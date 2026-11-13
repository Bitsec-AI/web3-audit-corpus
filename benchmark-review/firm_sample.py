"""Pick a reading sample of firm-review findings for the review app.

Per firm: critical/high/medium findings with text, at most two per audit, spread across years. Cantina audits that
republish a Spearbit audit (half or more of their finding titles match one Spearbit audit) are left out.

    .venv/bin/python -I benchmark-review/firm_sample.py --release data/release --per-firm 15
"""
import argparse
import re
from pathlib import Path

import duckdb

HERE = Path(__file__).resolve().parent
FIRMS = ["openzeppelin", "ottersec", "code4rena-zenith", "sherlock", "spearbit", "cantina"]


def norm(title):
    return re.sub(r"[^a-z0-9]+", " ", str(title).lower()).strip()


def cantina_republications(c, release):
    """Cantina engagements whose finding titles mostly match one Spearbit engagement."""
    rows = c.execute(f"""select firm_id, engagement_id, title from '{release}/findings.parquet'
                         where selected_for_stats and firm_id in ('spearbit', 'cantina')""").fetchall()
    titles = {}
    for firm, eid, title in rows:
        t = norm(title)
        if len(t) > 25:
            titles.setdefault((firm, eid), set()).add(t)
    spear = {eid: ts for (firm, eid), ts in titles.items() if firm == "spearbit"}
    dups = set()
    for (firm, eid), ts in titles.items():
        if firm == "cantina" and any(len(ts & s) / len(ts) >= 0.5 for s in spear.values()):
            dups.add(eid)
    return dups


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    ap.add_argument("--per-firm", type=int, default=15)
    ap.add_argument("--out", default=str(HERE / "firm_sample.txt"))
    args = ap.parse_args()
    c = duckdb.connect()
    c.execute(f"create view e as select * from read_csv_auto('{args.release}/engagements.csv', all_varchar=true)")
    dups = cantina_republications(c, args.release)
    df = c.execute(f"""select f.finding_uid, f.firm_id, f.engagement_id, try_cast(e.audit_year as int) yr
        from '{args.release}/findings.parquet' f join e using(engagement_id)
        where f.selected_for_stats and e.review_mode = 'firm_review' and f.severity in ('critical', 'high', 'medium')
          and f.body_text_status = 'present' and f.firm_id in (select unnest(?))""", [FIRMS]).df()
    df = df[~df.engagement_id.isin(dups)]
    picks = []
    for firm in FIRMS:
        g = df[df.firm_id == firm].sample(frac=1, random_state=13)
        g = g.groupby("engagement_id").head(2)  # at most two findings per audit
        by_year = [list(x.finding_uid) for _, x in g.groupby("yr")]
        chosen, i = [], 0
        while len(chosen) < args.per_firm and any(by_year):
            bucket = by_year[i % len(by_year)]
            if bucket:
                chosen.append(bucket.pop())
            i += 1
        picks += [(firm, uid) for uid in chosen]
    Path(args.out).write_text(
        f"# Firm-review reading sample: {args.per_firm} critical/high/medium findings per firm, at most 2 per audit, spread across years.\n"
        f"# Excludes {len(dups)} Cantina audits that republish a Spearbit audit. Built by firm_sample.py.\n"
        + "".join(f"{uid}  # {firm}\n" for firm, uid in picks))
    print(f"{len(picks)} findings, {len(dups)} Cantina republications excluded -> {args.out}")


if __name__ == "__main__":
    main()
