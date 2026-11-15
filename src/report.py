"""Reporting: KPIs, Excel workbook, e-mail-ready summary and Power BI export."""
from __future__ import annotations

from pathlib import Path

import pandas as pd
from openpyxl import Workbook
from openpyxl.formatting.rule import CellIsRule
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.datavalidation import DataValidation

from policy import SEVERITY_WEIGHT
from rules import RULES, Config, Dataset, _accounts_with_hr, privileged_memberships

SEVERITIES = ["critical", "high", "medium", "low"]
FONT = "Arial"


# --------------------------------------------------------------------------- #
# KPIs
# --------------------------------------------------------------------------- #
def _completed_reviews(ds: Dataset, cfg: Config) -> pd.DataFrame:
    cutoff = cfg.reference_date - pd.Timedelta(days=cfg.review_window_days)
    done = ds.reviews[ds.reviews["decision"].isin(["approved", "revoked"])
                      & (ds.reviews["decided_at"] >= cutoff)]
    return done[["account_id", "group_id"]].drop_duplicates()


def compute_kpis(ds: Dataset, findings: pd.DataFrame, cfg: Config) -> dict:
    enabled = ds.accounts[ds.accounts["enabled"]]
    priv = privileged_memberships(ds)
    priv = priv[priv["account_id"].isin(enabled["account_id"])]
    covered = priv.merge(_completed_reviews(ds, cfg), on=["account_id", "group_id"], how="inner")

    acc = _accounts_with_hr(ds)
    gone = acc[(~acc["enabled"]) & acc["disabled_at"].notna() & (acc["status"] == "terminated")]
    lag = (gone["disabled_at"] - gone["termination_date"]).dt.days

    overdue = ds.reviews[(ds.reviews["decision"] == "pending")
                         & (ds.reviews["due_date"] < cfg.reference_date)]
    n_with = int(findings["account_id"].nunique()) if not findings.empty else 0
    return {
        "reference_date": cfg.reference_date,
        "accounts_enabled": int(len(enabled)),
        "service_accounts_enabled": int((enabled["account_type"] == "service").sum()),
        "findings_total": int(len(findings)),
        "by_severity": {s: int((findings["severity"] == s).sum()) for s in SEVERITIES},
        "by_rule": {r: int((findings["rule_id"] == r).sum()) for r in RULES},
        "accounts_with_findings": n_with,
        "privileged_memberships": int(len(priv)),
        "privileged_reviewed": int(len(covered)),
        "overdue_reviews": int(len(overdue)),
        "avg_offboarding_lag_days": round(float(lag.mean()), 1) if len(lag) else 0.0,
    }


# --------------------------------------------------------------------------- #
# Excel
# --------------------------------------------------------------------------- #
ACHADOS_COLUMNS = [  # header, source column (None = filled in by the team), width
    ("ID", "finding_id", 9), ("Regra", "rule_id", 8), ("Severidade", "severity", 12),
    ("Conta", "account_id", 22), ("ID colaborador", "employee_id", 14),
    ("Departamento", "department", 24), ("Grupo", "group_id", 34),
    ("Detalhe", "detail", 72), ("Recomendação", "remediation", 62),
    ("Pontos de risco", "risk_points", 12), ("Detectado em", "detected_at", 13),
    ("Responsável", None, 18), ("Status", None, 16), ("Observações", None, 30),
]
HEADER_FILL = PatternFill("solid", start_color="1F3864", end_color="1F3864")
SEV_STYLE = {"critical": ("C00000", "FFFFFF"), "high": ("F4B183", "000000"),
             "medium": ("FFE699", "000000"), "low": ("C6E0B4", "000000")}
DATE_FMT = "dd/mm/yyyy"


def _style_header(ws, row: int, ncols: int) -> None:
    for c in range(1, ncols + 1):
        cell = ws.cell(row=row, column=c)
        cell.font = Font(name=FONT, bold=True, color="FFFFFF")
        cell.fill = HEADER_FILL
        cell.alignment = Alignment(vertical="center", wrap_text=True)


def write_excel(ds: Dataset, findings: pd.DataFrame, risk: pd.DataFrame,
                kpis: dict, cfg: Config, path: Path) -> None:
    wb = Workbook()
    n = len(findings)
    last = n + 1

    # ---- Achados --------------------------------------------------------- #
    wa = wb.active
    wa.title = "Achados"
    wa.append([h for h, _, _ in ACHADOS_COLUMNS])
    for r in findings.to_dict("records"):
        row = []
        for _, key, _ in ACHADOS_COLUMNS:
            if key is None:
                row.append(None)
            elif key == "detected_at":
                row.append(pd.Timestamp(r[key]).to_pydatetime())
            else:
                v = r[key]
                row.append(None if pd.isna(v) else (int(v) if key == "risk_points" else v))
        row[12] = "Aberto"
        wa.append(row)
    _style_header(wa, 1, len(ACHADOS_COLUMNS))
    for i, (_, _, width) in enumerate(ACHADOS_COLUMNS, start=1):
        wa.column_dimensions[get_column_letter(i)].width = width
    for r in range(2, last + 1):
        wa.cell(row=r, column=11).number_format = DATE_FMT
        wa.cell(row=r, column=8).alignment = Alignment(wrap_text=True, vertical="top")
        wa.cell(row=r, column=9).alignment = Alignment(wrap_text=True, vertical="top")
    wa.freeze_panes = "A2"
    wa.auto_filter.ref = f"A1:{get_column_letter(len(ACHADOS_COLUMNS))}{last}"
    for sev, (bg, fg) in SEV_STYLE.items():
        wa.conditional_formatting.add(
            f"C2:C{last}",
            CellIsRule(operator="equal", formula=[f'"{sev}"'],
                       fill=PatternFill("solid", start_color=bg, end_color=bg),
                       font=Font(name=FONT, color=fg, bold=sev == "critical")))
    dv = DataValidation(type="list", formula1='"Aberto,Em andamento,Resolvido,Risco aceito"',
                        allow_blank=False)
    wa.add_data_validation(dv)
    dv.add(f"M2:M{last}")

    # ---- Resumo ---------------------------------------------------------- #
    ws = wb.create_sheet("Resumo", 0)
    ws["A1"] = "Revisão de acessos (IAM) — resumo"
    ws["A1"].font = Font(name=FONT, bold=True, size=14)
    ws["A2"], ws["B2"] = "Data de referência", cfg.reference_date.to_pydatetime()
    ws["B2"].number_format = DATE_FMT
    ws["A3"], ws["B3"] = "Origem dos dados", "Dados sintéticos gerados por src/generate_data.py"
    ws["A4"], ws["B4"] = ("Como usar",
                          "Edite Responsável, Status e Observações na aba Achados (colunas L a N); "
                          "os totais abaixo recalculam sozinhos.")

    ws["A6"] = "Achados por severidade"
    ws["A7"], ws["B7"], ws["C7"], ws["D7"] = "Severidade", "Total", "Em aberto", "Resolvidos"
    _style_header(ws, 7, 4)
    for i, sev in enumerate(SEVERITIES):
        r = 8 + i
        ws.cell(row=r, column=1, value=sev)
        ws.cell(row=r, column=2, value=f"=COUNTIF(Achados!$C:$C,A{r})")
        ws.cell(row=r, column=3, value=f'=COUNTIFS(Achados!$C:$C,A{r},Achados!$M:$M,"Aberto")')
        ws.cell(row=r, column=4, value=f'=COUNTIFS(Achados!$C:$C,A{r},Achados!$M:$M,"Resolvido")')
    ws["A12"] = "Total"
    for col in "BCD":
        ws[f"{col}12"] = f"=SUM({col}8:{col}11)"
        ws[f"{col}12"].font = Font(name=FONT, bold=True)
    ws["A12"].font = Font(name=FONT, bold=True)

    ws["A14"] = "Achados por regra"
    ws["A15"], ws["B15"], ws["C15"], ws["D15"] = "Regra", "Descrição", "Total", "Em aberto"
    _style_header(ws, 15, 4)
    for i, (rid, (_, title, _)) in enumerate(RULES.items()):
        r = 16 + i
        ws.cell(row=r, column=1, value=rid)
        ws.cell(row=r, column=2, value=title)
        ws.cell(row=r, column=3, value=f"=COUNTIF(Achados!$B:$B,A{r})")
        ws.cell(row=r, column=4, value=f'=COUNTIFS(Achados!$B:$B,A{r},Achados!$M:$M,"Aberto")')

    base = 16 + len(RULES) + 1  # blank row, then the KPI block
    ws.cell(row=base, column=1, value="Indicadores (valores fixos calculados pelo script)")
    for c, h in enumerate(["Indicador", "Valor", "Observação"], start=1):
        ws.cell(row=base + 1, column=c, value=h)
    _style_header(ws, base + 1, 3)
    k = kpis
    rows = [
        ("Contas ativas analisadas", k["accounts_enabled"], "0", "Inclui contas de serviço"),
        ("Contas com pelo menos um achado", k["accounts_with_findings"], "0", ""),
        ("% de contas ativas com achados", f"=B{base + 3}/B{base + 2}", "0.0%", "Fórmula"),
        ("Acessos privilegiados (contas ativas)", k["privileged_memberships"], "0",
         "Grupos de nível high ou critical"),
        ("Com revisão concluída na janela", k["privileged_reviewed"], "0",
         f"Janela de {cfg.review_window_days} dias"),
        ("Cobertura da revisão de acessos privilegiados", f"=B{base + 6}/B{base + 5}", "0.0%",
         "Fórmula"),
        ("Revisões pendentes e vencidas", k["overdue_reviews"], "0", ""),
        ("Tempo médio de desativação após desligamento (dias)",
         k["avg_offboarding_lag_days"], "0.0", "Apenas contas já desativadas"),
    ]
    for i, (label, value, fmt, note) in enumerate(rows):
        r = base + 2 + i
        ws.cell(row=r, column=1, value=label)
        cell = ws.cell(row=r, column=2, value=value)
        cell.number_format = fmt
        ws.cell(row=r, column=3, value=note)
    for rr in (6, 14, base):
        ws.cell(row=rr, column=1).font = Font(name=FONT, bold=True, size=11)
    ws.column_dimensions["A"].width = 48
    ws.column_dimensions["B"].width = 58
    ws.column_dimensions["C"].width = 30
    ws.column_dimensions["D"].width = 14

    # ---- Top contas em risco -------------------------------------------- #
    wt = wb.create_sheet("Top_contas")
    wt.append(["Conta", "Departamento", "Tipo", "Nº de achados", "Pontos de risco", "Regras"])
    _style_header(wt, 1, 6)
    for i, r in enumerate(risk.head(25).to_dict("records"), start=2):
        wt.append([r["account_id"], r["department"], r["account_type"],
                   f"=COUNTIF(Achados!$D:$D,A{i})",
                   f"=SUMIFS(Achados!$J:$J,Achados!$D:$D,A{i})", r["rules"]])
    for col, w in zip("ABCDEF", [24, 26, 10, 14, 15, 28]):
        wt.column_dimensions[col].width = w
    wt.freeze_panes = "A2"

    # ---- Revisões pendentes --------------------------------------------- #
    wr = wb.create_sheet("Revisoes_pendentes")
    wr.append(["Revisão", "Conta", "Grupo", "Revisor", "Ciclo", "Prazo", "Dias de atraso"])
    _style_header(wr, 1, 7)
    od = ds.reviews[(ds.reviews["decision"] == "pending")
                    & (ds.reviews["due_date"] < cfg.reference_date)]
    od = od.sort_values(["due_date", "review_id"])
    for i, r in enumerate(od.to_dict("records"), start=2):
        wr.append([r["review_id"], r["account_id"], r["group_id"], r["reviewer_id"], r["cycle"],
                   r["due_date"].to_pydatetime(), f"=Resumo!$B$2-F{i}"])
        wr.cell(row=i, column=6).number_format = DATE_FMT
        wr.cell(row=i, column=7).number_format = "0"
    for col, w in zip("ABCDEFG", [12, 22, 24, 22, 10, 13, 14]):
        wr.column_dimensions[col].width = w
    wr.freeze_panes = "A2"

    # Arial everywhere, preserving bold/colour already set.
    for sheet in wb.worksheets:
        for row in sheet.iter_rows():
            for cell in row:
                f = cell.font
                cell.font = Font(name=FONT, size=f.size if f.size and f.size != 11 else 10,
                                 bold=f.bold, italic=f.italic, color=f.color)
    path.parent.mkdir(parents=True, exist_ok=True)
    wb.save(path)


# --------------------------------------------------------------------------- #
# Markdown summary (ready to paste into an e-mail)
# --------------------------------------------------------------------------- #
def write_summary_md(findings: pd.DataFrame, risk: pd.DataFrame, kpis: dict,
                     cfg: Config, path: Path) -> None:
    k = kpis
    pct_accounts = k["accounts_with_findings"] / k["accounts_enabled"] if k["accounts_enabled"] else 0
    cover = k["privileged_reviewed"] / k["privileged_memberships"] if k["privileged_memberships"] else 0
    sev = k["by_severity"]
    lines = [
        f"# Resumo da revisão de acessos — {cfg.reference_date:%d/%m/%Y}",
        "",
        "> Dados sintéticos (fictícios), gerados por `src/generate_data.py`.",
        "",
        "## Visão geral",
        "",
        f"- Contas ativas analisadas: **{k['accounts_enabled']}** "
        f"({k['service_accounts_enabled']} de serviço)",
        f"- Achados: **{k['findings_total']}**, em **{k['accounts_with_findings']}** contas "
        f"({pct_accounts:.1%} das contas ativas)",
        f"- Por severidade: critical **{sev['critical']}** · high **{sev['high']}** · "
        f"medium **{sev['medium']}** · low **{sev['low']}**",
        f"- Cobertura da revisão de acessos privilegiados (últimos {cfg.review_window_days} dias): "
        f"**{cover:.1%}** ({k['privileged_reviewed']} de {k['privileged_memberships']})",
        f"- Revisões pendentes e vencidas: **{k['overdue_reviews']}**",
        f"- Tempo médio para desativar contas após o desligamento: "
        f"**{k['avg_offboarding_lag_days']} dias**",
        "",
        "## Achados por regra",
        "",
        "| Regra | Descrição | Qtde |",
        "|---|---|---:|",
    ]
    for rid, (_, title, _) in RULES.items():
        if k["by_rule"][rid]:
            lines.append(f"| {rid} | {title} | {k['by_rule'][rid]} |")
    lines += ["", "## Top 5 contas em risco", "", "| Conta | Área | Pontos | Regras |",
              "|---|---|---:|---|"]
    for r in risk.head(5).to_dict("records"):
        lines.append(f"| {r['account_id']} | {r['department']} | {r['risk_points']} | {r['rules']} |")

    lines += ["", "## Ações recomendadas", ""]
    top_rules = (findings.groupby("rule_id")["risk_points"].sum()
                 .sort_values(ascending=False).head(4).index)
    for i, rid in enumerate(top_rules, start=1):
        lines.append(f"{i}. **{RULES[rid][1]}** ({k['by_rule'][rid]} achados): {RULES[rid][2]}")
    lines.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


# --------------------------------------------------------------------------- #
# Power BI export (star-like model, typed columns, ready for "Get data > Folder")
# --------------------------------------------------------------------------- #
def export_powerbi(ds: Dataset, findings: pd.DataFrame, cfg: Config, out_dir: Path) -> None:
    out = out_dir / "powerbi"
    out.mkdir(parents=True, exist_ok=True)
    ref = cfg.reference_date.normalize()

    def save(df: pd.DataFrame, name: str) -> None:
        df.to_csv(out / f"{name}.csv", index=False, date_format="%Y-%m-%d")

    acc = _accounts_with_hr(ds).rename(columns={"status": "hr_status"})
    acc["offboarding_lag_days"] = (acc["disabled_at"] - acc["termination_date"]).dt.days
    acc["days_since_last_logon"] = (ref - acc["last_logon"]).dt.days
    save(acc[["account_id", "employee_id", "display_name", "department", "account_type",
              "enabled", "created_at", "last_logon", "disabled_at", "owner_employee_id",
              "hr_status", "termination_date", "offboarding_lag_days",
              "days_since_last_logon"]], "dim_account")

    groups = ds.groups.copy()
    groups["is_privileged"] = groups["privilege_level"].isin(["high", "critical"])
    save(groups, "dim_group")

    mem = ds.memberships.merge(groups[["group_id", "is_privileged"]], on="group_id", how="left")
    done = _completed_reviews(ds, cfg).assign(reviewed_in_window=True)
    mem = mem.merge(done, on=["account_id", "group_id"], how="left")
    mem["reviewed_in_window"] = mem["reviewed_in_window"].eq(True)
    save(mem, "fact_membership")

    rev = ds.reviews.copy()
    rev["is_overdue"] = (rev["decision"] == "pending") & (rev["due_date"] < ref)
    rev["days_overdue"] = ((ref - rev["due_date"]).dt.days).where(rev["is_overdue"], 0)
    save(rev, "fact_review")

    fnd = findings.copy()
    fnd["severity_order"] = fnd["severity"].map({s: i + 1 for i, s in enumerate(SEVERITIES)})
    save(fnd[["finding_id", "rule_id", "severity", "severity_order", "account_id",
              "employee_id", "department", "group_id", "detail", "remediation",
              "risk_points", "detected_at"]], "fact_finding")

    save(pd.DataFrame({"severity": SEVERITIES,
                       "severity_order": range(1, len(SEVERITIES) + 1),
                       "weight": [SEVERITY_WEIGHT[s] for s in SEVERITIES]}), "dim_severity")
    save(pd.DataFrame([{"rule_id": k, "rule_name": v[0], "title": v[1], "remediation": v[2]}
                       for k, v in RULES.items()]), "dim_rule")
