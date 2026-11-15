#!/usr/bin/env python3
"""Run the IAM access review: load data -> apply rules -> write reports.

Usage:
    python src/run_review.py                      # uses data/ and writes to output/
    python src/run_review.py --dormant-days 60    # tighter policy
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from report import compute_kpis, export_powerbi, write_excel, write_summary_md
from rules import Config, account_risk, load_dataset, run_all


def main(argv: list[str] | None = None) -> None:
    root = Path(__file__).resolve().parents[1]
    p = argparse.ArgumentParser(description="Run the IAM access review.")
    p.add_argument("--data", default=str(root / "data"))
    p.add_argument("--out", default=str(root / "output"))
    p.add_argument("--ref-date", default=None,
                   help="YYYY-MM-DD (default: the date stored in data/metadata.json, else today)")
    p.add_argument("--dormant-days", type=int, default=90)
    p.add_argument("--review-window-days", type=int, default=180)
    p.add_argument("--privileged-threshold", type=int, default=3)
    p.add_argument("--deprovision-sla-days", type=int, default=2)
    args = p.parse_args(argv)

    data_dir, out_dir = Path(args.data), Path(args.out)
    ref = args.ref_date
    meta_file = data_dir / "metadata.json"
    if ref is None and meta_file.exists():
        ref = json.loads(meta_file.read_text(encoding="utf-8")).get("reference_date")
    cfg = Config(
        reference_date=pd.Timestamp(ref) if ref else pd.Timestamp.today().normalize(),
        dormant_days=args.dormant_days,
        review_window_days=args.review_window_days,
        privileged_groups_threshold=args.privileged_threshold,
        deprovision_sla_days=args.deprovision_sla_days,
    )

    ds = load_dataset(data_dir)
    findings = run_all(ds, cfg)
    risk = account_risk(findings, ds)
    kpis = compute_kpis(ds, findings, cfg)

    out_dir.mkdir(parents=True, exist_ok=True)
    findings.to_csv(out_dir / "findings.csv", index=False, date_format="%Y-%m-%d")
    write_excel(ds, findings, risk, kpis, cfg, out_dir / "access_review_report.xlsx")
    write_summary_md(findings, risk, kpis, cfg, out_dir / "summary.md")
    export_powerbi(ds, findings, cfg, out_dir)

    sev = kpis["by_severity"]
    print(f"Revisão de acessos — referência {cfg.reference_date:%d/%m/%Y}")
    print(f"  Contas ativas: {kpis['accounts_enabled']} | achados: {kpis['findings_total']} "
          f"em {kpis['accounts_with_findings']} contas")
    print(f"  critical={sev['critical']} high={sev['high']} "
          f"medium={sev['medium']} low={sev['low']}")
    print(f"  Relatórios em: {out_dir}")


if __name__ == "__main__":
    main()
