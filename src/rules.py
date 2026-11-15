"""Access-review detection rules.

Each rule is a small, pure function: (Dataset, Config) -> DataFrame of findings.
`run_all` runs every rule, enriches the result and returns one findings table.

Rule catalogue
    R01 orphan_account                 active account of a terminated person / no HR record
    R02 dormant_account                enabled account without a recent logon
    R03 sod_conflict                   segregation-of-duties conflict
    R04 cross_department_privilege     privileged group owned by another department
    R05 excessive_privileged_groups    too many privileged groups on one account
    R06 unreviewed_privileged_access   privileged membership without a recent review
    R07 revoked_not_removed            review said "revoke", access is still there
    R08 overdue_review                 pending review past its due date
    R09 late_deprovisioning            account disabled too long after termination
    R10 service_account_without_owner  service account with no owner
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pandas as pd

from policy import PRIVILEGED_LEVELS, SEVERITY_WEIGHT, SOD_CONFLICTS

FINDING_COLUMNS = ["rule_id", "severity", "account_id", "employee_id",
                   "department", "group_id", "detail"]

RULES = {
    "R01": ("orphan_account",
            "Conta ativa de colaborador desligado ou sem vínculo no RH",
            "Desabilitar a conta, revisar a atividade após o desligamento e remover os acessos."),
    "R02": ("dormant_account",
            "Conta ativa sem logon recente",
            "Confirmar a necessidade com o gestor/responsável; desabilitar se não for mais usada."),
    "R03": ("sod_conflict",
            "Conflito de segregação de funções (SoD)",
            "Remover um dos dois acessos ou documentar controle compensatório aprovado."),
    "R04": ("cross_department_privilege",
            "Acesso privilegiado a grupo de outra área",
            "Validar a justificativa de negócio com o dono do grupo; remover se não houver."),
    "R05": ("excessive_privileged_groups",
            "Conta com muitos grupos privilegiados",
            "Aplicar o princípio do menor privilégio e separar contas administrativas."),
    "R06": ("unreviewed_privileged_access",
            "Acesso privilegiado sem revisão recente",
            "Incluir o acesso no próximo ciclo de revisão e cobrar o revisor."),
    "R07": ("revoked_not_removed",
            "Revisão decidiu revogar, mas o acesso continua",
            "Executar a revogação decidida na revisão e registrar a evidência."),
    "R08": ("overdue_review",
            "Revisão de acesso pendente além do prazo",
            "Escalar ao gestor do revisor e fixar um novo prazo."),
    "R09": ("late_deprovisioning",
            "Conta desabilitada depois do prazo após o desligamento",
            "Revisar o processo de desligamento (RH → TI) e o SLA de desativação."),
    "R10": ("service_account_without_owner",
            "Conta de serviço sem responsável definido",
            "Definir um responsável (owner) ou desativar a conta."),
}


@dataclass(frozen=True)
class Config:
    reference_date: pd.Timestamp
    dormant_days: int = 90
    review_window_days: int = 180
    privileged_groups_threshold: int = 3
    deprovision_sla_days: int = 2


@dataclass
class Dataset:
    employees: pd.DataFrame
    accounts: pd.DataFrame
    groups: pd.DataFrame
    memberships: pd.DataFrame
    reviews: pd.DataFrame


def load_dataset(data_dir: str | Path) -> Dataset:
    d = Path(data_dir)
    return Dataset(
        employees=pd.read_csv(d / "employees.csv", parse_dates=["hire_date", "termination_date"]),
        accounts=pd.read_csv(d / "accounts.csv",
                             parse_dates=["created_at", "last_logon", "disabled_at"]),
        groups=pd.read_csv(d / "groups.csv"),
        memberships=pd.read_csv(d / "memberships.csv", parse_dates=["granted_at"]),
        reviews=pd.read_csv(d / "reviews.csv",
                            parse_dates=["opened_at", "due_date", "decided_at"]),
    )


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _clean(value):
    return None if pd.isna(value) else value


def _frame(rows: list[dict]) -> pd.DataFrame:
    return pd.DataFrame(rows, columns=FINDING_COLUMNS)


def _row(rule_id: str, severity: str, acc: dict, detail: str, group_id=None) -> dict:
    return {
        "rule_id": rule_id, "severity": severity, "account_id": acc["account_id"],
        "employee_id": _clean(acc.get("employee_id")), "department": acc["department"],
        "group_id": group_id, "detail": detail,
    }


def _account_map(ds: Dataset) -> dict[str, dict]:
    return {a["account_id"]: a for a in ds.accounts.to_dict("records")}


def _accounts_with_hr(ds: Dataset) -> pd.DataFrame:
    hr = ds.employees[["employee_id", "status", "termination_date"]]
    return ds.accounts.merge(hr, on="employee_id", how="left")


def privileged_memberships(ds: Dataset) -> pd.DataFrame:
    """Memberships in high/critical groups, with group level and owner."""
    g = ds.groups[ds.groups["privilege_level"].isin(PRIVILEGED_LEVELS)]
    g = g[["group_id", "privilege_level", "owner_department"]]
    return ds.memberships.merge(g, on="group_id", how="inner")


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #
def r01_orphan_accounts(ds: Dataset, cfg: Config) -> pd.DataFrame:
    acc = _accounts_with_hr(ds)
    acc = acc[(acc["account_type"] == "user") & acc["enabled"]]
    bad = acc[acc["status"].isna() | (acc["status"] == "terminated")]
    rows = []
    for r in bad.to_dict("records"):
        if pd.isna(r["status"]):
            severity, detail = "high", "Conta de usuário ativa sem vínculo com o RH"
        else:
            term, last = r["termination_date"], r["last_logon"]
            used_after = pd.notna(last) and last > term
            severity = "critical" if used_after else "high"
            detail = f"Colaborador desligado em {term:%d/%m/%Y}; conta ainda ativa"
            if used_after:
                detail += f" e com logon em {last:%d/%m/%Y}, após o desligamento"
        rows.append(_row("R01", severity, r, detail))
    return _frame(rows)


def r02_dormant_accounts(ds: Dataset, cfg: Config) -> pd.DataFrame:
    acc = _accounts_with_hr(ds)
    acc = acc[acc["enabled"]]
    # People on leave are expected to be inactive; terminated people are R01.
    acc = acc[(acc["account_type"] == "service") | (acc["status"] == "active")]
    cutoff = cfg.reference_date - pd.Timedelta(days=cfg.dormant_days)
    dormant = acc[acc["last_logon"].isna() | (acc["last_logon"] < cutoff)]
    privileged = set(privileged_memberships(ds)["account_id"])
    rows = []
    for r in dormant.to_dict("records"):
        severity = "high" if r["account_id"] in privileged else "medium"
        if pd.isna(r["last_logon"]):
            detail = "Conta ativa que nunca realizou logon"
        else:
            days = (cfg.reference_date - r["last_logon"]).days
            detail = f"Sem logon há {days} dias (limite: {cfg.dormant_days})"
        if r["account_id"] in privileged:
            detail += "; possui acesso privilegiado"
        rows.append(_row("R02", severity, r, detail))
    return _frame(rows)


def r03_sod_conflicts(ds: Dataset, cfg: Config) -> pd.DataFrame:
    accounts = _account_map(ds)
    enabled = [a for a, r in accounts.items() if r["enabled"]]
    held = (ds.memberships[ds.memberships["account_id"].isin(enabled)]
            .groupby("account_id")["group_id"].apply(set))
    rows = []
    for acc_id, groups in held.items():
        for a, b, severity, why in SOD_CONFLICTS:
            if a in groups and b in groups:
                rows.append(_row("R03", severity, accounts[acc_id],
                                 f"{why}: {a} + {b}", group_id=f"{a} + {b}"))
    return _frame(rows)


def r04_cross_department_privilege(ds: Dataset, cfg: Config) -> pd.DataFrame:
    m = privileged_memberships(ds).merge(
        ds.accounts[["account_id", "department", "account_type", "enabled"]],
        on="account_id")
    m = m[(m["account_type"] == "user") & m["enabled"]
          & (m["department"] != m["owner_department"])]
    accounts = _account_map(ds)
    rows = []
    for r in m.to_dict("records"):
        detail = (f"Conta de {r['department']} com acesso {r['privilege_level']} ao grupo "
                  f"{r['group_id']} (dono: {r['owner_department']})")
        rows.append(_row("R04", "high", accounts[r["account_id"]], detail, r["group_id"]))
    return _frame(rows)


def r05_excessive_privileged_groups(ds: Dataset, cfg: Config) -> pd.DataFrame:
    accounts = _account_map(ds)
    enabled = ds.accounts.loc[ds.accounts["enabled"], "account_id"]
    priv = privileged_memberships(ds)
    priv = priv[priv["account_id"].isin(enabled)]
    grouped = priv.groupby("account_id")["group_id"].apply(sorted)
    rows = []
    for acc_id, groups in grouped.items():
        n = len(groups)
        if n >= cfg.privileged_groups_threshold:
            severity = "high" if n > cfg.privileged_groups_threshold else "medium"
            rows.append(_row("R05", severity, accounts[acc_id],
                             f"Membro de {n} grupos privilegiados: {', '.join(groups)}"))
    return _frame(rows)


def r06_unreviewed_privileged_access(ds: Dataset, cfg: Config) -> pd.DataFrame:
    accounts = _account_map(ds)
    priv = privileged_memberships(ds)
    priv = priv[priv["account_id"].isin(ds.accounts.loc[ds.accounts["enabled"], "account_id"])]
    cutoff = cfg.reference_date - pd.Timedelta(days=cfg.review_window_days)
    done = ds.reviews[ds.reviews["decision"].isin(["approved", "revoked"])
                      & (ds.reviews["decided_at"] >= cutoff)]
    done = done[["account_id", "group_id"]].drop_duplicates()
    merged = priv.merge(done, on=["account_id", "group_id"], how="left", indicator=True)
    missing = merged[merged["_merge"] == "left_only"]
    rows = []
    for r in missing.to_dict("records"):
        severity = "high" if r["privilege_level"] == "critical" else "medium"
        detail = (f"Acesso {r['privilege_level']} ao grupo {r['group_id']} sem revisão "
                  f"concluída nos últimos {cfg.review_window_days} dias")
        rows.append(_row("R06", severity, accounts[r["account_id"]], detail, r["group_id"]))
    return _frame(rows)


def r07_revoked_not_removed(ds: Dataset, cfg: Config) -> pd.DataFrame:
    accounts = _account_map(ds)
    revoked = ds.reviews[ds.reviews["decision"] == "revoked"]
    still = revoked.merge(ds.memberships[["account_id", "group_id"]],
                          on=["account_id", "group_id"], how="inner")
    rows = []
    for r in still.to_dict("records"):
        detail = (f"Revisão de {r['decided_at']:%d/%m/%Y} decidiu revogar o acesso a "
                  f"{r['group_id']}, mas a conta continua no grupo")
        rows.append(_row("R07", "high", accounts[r["account_id"]], detail, r["group_id"]))
    return _frame(rows)


def r08_overdue_reviews(ds: Dataset, cfg: Config) -> pd.DataFrame:
    accounts = _account_map(ds)
    pending = ds.reviews[(ds.reviews["decision"] == "pending")
                         & (ds.reviews["due_date"] < cfg.reference_date)]
    rows = []
    for r in pending.to_dict("records"):
        late = (cfg.reference_date - r["due_date"]).days
        severity = "medium" if late >= 30 else "low"
        detail = (f"Revisão do grupo {r['group_id']} pendente há {late} dias além do prazo "
                  f"(revisor: {r['reviewer_id']})")
        rows.append(_row("R08", severity, accounts[r["account_id"]], detail, r["group_id"]))
    return _frame(rows)


def r09_late_deprovisioning(ds: Dataset, cfg: Config) -> pd.DataFrame:
    acc = _accounts_with_hr(ds)
    acc = acc[(~acc["enabled"]) & acc["disabled_at"].notna() & (acc["status"] == "terminated")]
    rows = []
    for r in acc.to_dict("records"):
        lag = (r["disabled_at"] - r["termination_date"]).days
        if lag > cfg.deprovision_sla_days:
            severity = "medium" if lag > 7 else "low"
            detail = (f"Conta desabilitada {lag} dias após o desligamento "
                      f"(SLA: {cfg.deprovision_sla_days} dias)")
            rows.append(_row("R09", severity, r, detail))
    return _frame(rows)


def r10_service_account_without_owner(ds: Dataset, cfg: Config) -> pd.DataFrame:
    acc = ds.accounts[(ds.accounts["account_type"] == "service") & ds.accounts["enabled"]
                      & ds.accounts["owner_employee_id"].isna()]
    privileged = set(privileged_memberships(ds)["account_id"])
    rows = []
    for r in acc.to_dict("records"):
        severity = "high" if r["account_id"] in privileged else "medium"
        rows.append(_row("R10", severity, r, "Conta de serviço sem responsável (owner) definido"))
    return _frame(rows)


RULE_FUNCTIONS = [
    r01_orphan_accounts, r02_dormant_accounts, r03_sod_conflicts,
    r04_cross_department_privilege, r05_excessive_privileged_groups,
    r06_unreviewed_privileged_access, r07_revoked_not_removed, r08_overdue_reviews,
    r09_late_deprovisioning, r10_service_account_without_owner,
]


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def run_all(ds: Dataset, cfg: Config) -> pd.DataFrame:
    """Run every rule and return a single, enriched findings table."""
    frames = [f for f in (fn(ds, cfg) for fn in RULE_FUNCTIONS) if not f.empty]
    if not frames:
        return pd.DataFrame(columns=FINDING_COLUMNS + [
            "finding_id", "rule_name", "title", "remediation", "risk_points", "detected_at"])
    findings = pd.concat(frames, ignore_index=True)

    # Accounts already flagged as orphan are fixed by disabling them: do not
    # also ask for their privileged access to be reviewed (avoids double counting).
    orphans = set(findings.loc[findings["rule_id"] == "R01", "account_id"])
    findings = findings[~((findings["rule_id"] == "R06") & findings["account_id"].isin(orphans))]

    findings["rule_name"] = findings["rule_id"].map({k: v[0] for k, v in RULES.items()})
    findings["title"] = findings["rule_id"].map({k: v[1] for k, v in RULES.items()})
    findings["remediation"] = findings["rule_id"].map({k: v[2] for k, v in RULES.items()})
    findings["risk_points"] = findings["severity"].map(SEVERITY_WEIGHT)
    findings["detected_at"] = cfg.reference_date.normalize()
    findings = (findings.sort_values(["risk_points", "rule_id", "account_id"],
                                     ascending=[False, True, True], kind="stable")
                .reset_index(drop=True))
    findings.insert(0, "finding_id", [f"F{i + 1:04d}" for i in range(len(findings))])
    return findings


def account_risk(findings: pd.DataFrame, ds: Dataset) -> pd.DataFrame:
    """One row per account with findings, ranked by risk points."""
    if findings.empty:
        return pd.DataFrame(columns=["account_id", "department", "account_type",
                                     "findings", "risk_points", "rules"])
    grp = findings.groupby("account_id").agg(
        findings=("finding_id", "count"),
        risk_points=("risk_points", "sum"),
        rules=("rule_id", lambda s: ", ".join(sorted(set(s)))),
    ).reset_index()
    info = ds.accounts[["account_id", "department", "account_type"]]
    out = grp.merge(info, on="account_id", how="left")
    out = out.sort_values(["risk_points", "findings", "account_id"],
                          ascending=[False, False, True], kind="stable").reset_index(drop=True)
    return out[["account_id", "department", "account_type", "findings", "risk_points", "rules"]]
