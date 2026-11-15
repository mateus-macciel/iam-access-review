#!/usr/bin/env python3
"""Synthetic, Active Directory-like dataset for the IAM access review demo.

Everything produced here is FICTITIOUS.  Names are composed at random from
generic first-name / surname lists, and nothing comes from, or mimics the
configuration of, any real organisation.

Anomalies (orphan accounts, SoD conflicts, privilege creep, ...) are planted on
purpose so that the detection rules and the dashboard have a story to tell.
The output is fully reproducible: same --seed and --ref-date, same files.

Usage:
    python src/generate_data.py --employees 400 --seed 42 --ref-date 2026-11-13
"""
from __future__ import annotations

import argparse
import json
import math
import unicodedata
from datetime import date, timedelta
from pathlib import Path

import numpy as np
import pandas as pd

from policy import PRIVILEGED_LEVELS, SOD_CONFLICTS

# --------------------------------------------------------------------------- #
# Catalogues
# --------------------------------------------------------------------------- #
FIRST_NAMES = [
    "Ana", "Bruno", "Camila", "Daniel", "Eduarda", "Felipe", "Gabriela", "Henrique",
    "Isabela", "João", "Karina", "Lucas", "Mariana", "Nicolas", "Olívia", "Pedro",
    "Rafaela", "Sérgio", "Tatiane", "Vinícius", "Beatriz", "Caio", "Débora", "Eduardo",
    "Fernanda", "Guilherme", "Helena", "Igor", "Juliana", "Leonardo", "Marcelo",
    "Natália", "Otávio", "Patrícia", "Rodrigo", "Sabrina", "Thiago", "Valéria",
    "Wagner", "Yasmin",
]
LAST_NAMES = [
    "Almeida", "Barbosa", "Cardoso", "Dias", "Esteves", "Ferreira", "Gomes", "Henriques",
    "Ibrahim", "Jesus", "Lima", "Moreira", "Nogueira", "Oliveira", "Pereira", "Queiroz",
    "Ribeiro", "Santos", "Teixeira", "Uchoa", "Vieira", "Xavier", "Azevedo", "Batista",
    "Castro", "Duarte", "Farias", "Guimarães", "Lopes", "Machado", "Nascimento", "Pinto",
    "Rocha", "Siqueira", "Tavares", "Araújo", "Campos", "Freitas", "Monteiro", "Ramos",
]

# department -> (share of headcount, job titles)
DEPARTMENTS = {
    "Tecnologia": (0.24, ["Analista de Sistemas", "Engenheiro de Software",
                          "Analista de Infraestrutura", "Analista de Suporte"]),
    "Segurança da Informação": (0.06, ["Analista de Segurança", "Analista de IAM",
                                       "Analista de SOC"]),
    "Financeiro": (0.12, ["Analista Financeiro", "Analista de Contas a Pagar", "Contador"]),
    "Operações": (0.18, ["Analista de Operações", "Analista de Pagamentos",
                         "Assistente de Operações"]),
    "Atendimento": (0.16, ["Atendente", "Analista de Atendimento"]),
    "Comercial": (0.10, ["Executivo de Contas", "Analista Comercial"]),
    "Jurídico": (0.03, ["Advogado", "Analista Jurídico"]),
    "RH": (0.04, ["Analista de RH", "Business Partner de RH"]),
    "Risco e Compliance": (0.07, ["Analista de Risco", "Analista de Compliance"]),
}

# group_id, description, privilege level, owner department
GROUPS = [
    ("GG-All-Employees", "Todos os colaboradores", "low", "Tecnologia"),
    ("GG-VPN-Users", "Acesso à VPN corporativa", "low", "Tecnologia"),
    ("GG-Office365-E3", "Licença Microsoft 365 E3", "low", "Tecnologia"),
    ("GG-Intranet-Editors", "Edição da intranet", "low", "RH"),
    ("GG-CRM-Users", "Uso do CRM", "low", "Comercial"),
    ("GG-Fin-Reports-Read", "Leitura de relatórios financeiros", "medium", "Financeiro"),
    ("GG-Legal-Contracts", "Acesso a contratos jurídicos", "medium", "Jurídico"),
    ("GG-DB-ReadOnly", "Leitura em bancos de dados", "medium", "Tecnologia"),
    ("GG-Dev-Repo-Write", "Escrita em repositórios de código", "medium", "Tecnologia"),
    ("GG-Audit-Log-Read", "Leitura de logs de auditoria", "medium", "Risco e Compliance"),
    ("GG-Fin-AP-Create", "Criação de contas a pagar", "high", "Financeiro"),
    ("GG-Fin-AP-Approve", "Aprovação de contas a pagar", "high", "Financeiro"),
    ("GG-Pay-Initiate", "Iniciação de pagamentos", "high", "Operações"),
    ("GG-Pay-Approve", "Aprovação de pagamentos", "critical", "Operações"),
    ("GG-Prod-Deploy", "Deploy em produção", "high", "Tecnologia"),
    ("GG-SIEM-Analysts", "Analistas do SIEM", "high", "Segurança da Informação"),
    ("GG-HR-Payroll", "Folha de pagamento", "high", "RH"),
    ("GG-DB-Admins", "Administração de bancos de dados", "critical", "Tecnologia"),
    ("GG-Server-Admins", "Administração de servidores", "critical", "Tecnologia"),
    ("GG-IAM-Admins", "Administração de identidades e acessos", "critical",
     "Segurança da Informação"),
]
GROUP_OWNER = {g[0]: g[3] for g in GROUPS}
GROUP_LEVEL = {g[0]: g[2] for g in GROUPS}

BASE_GROUPS = [("GG-All-Employees", 1.0), ("GG-VPN-Users", 0.95), ("GG-Office365-E3", 0.98)]

# department -> [(group, probability of membership)]
DEPT_GROUPS = {
    "Tecnologia": [("GG-Dev-Repo-Write", 0.70), ("GG-DB-ReadOnly", 0.35),
                   ("GG-Prod-Deploy", 0.12), ("GG-DB-Admins", 0.05),
                   ("GG-Server-Admins", 0.06)],
    "Segurança da Informação": [("GG-SIEM-Analysts", 0.70), ("GG-IAM-Admins", 0.12),
                                ("GG-DB-ReadOnly", 0.15)],
    "Financeiro": [("GG-Fin-Reports-Read", 0.80), ("GG-Fin-AP-Create", 0.25),
                   ("GG-Fin-AP-Approve", 0.12)],
    "Operações": [("GG-Pay-Initiate", 0.30), ("GG-Pay-Approve", 0.08),
                  ("GG-Fin-Reports-Read", 0.20)],
    "Atendimento": [("GG-CRM-Users", 0.95)],
    "Comercial": [("GG-CRM-Users", 0.90), ("GG-Intranet-Editors", 0.15)],
    "Jurídico": [("GG-Legal-Contracts", 0.80)],
    "RH": [("GG-HR-Payroll", 0.35), ("GG-Intranet-Editors", 0.30)],
    "Risco e Compliance": [("GG-Audit-Log-Read", 0.60), ("GG-Fin-Reports-Read", 0.40)],
}

# A typical privileged group per department (used for planted anomalies).
DEPT_PRIV_GROUP = {
    "Tecnologia": "GG-Server-Admins",
    "Segurança da Informação": "GG-IAM-Admins",
    "Financeiro": "GG-Fin-AP-Approve",
    "Operações": "GG-Pay-Initiate",
    "RH": "GG-HR-Payroll",
}

# name, department, groups, days since last logon (None = active), has an owner?
SERVICE_ACCOUNTS = [
    ("svc-backup", "Tecnologia", ["GG-Server-Admins"], None, True),
    ("svc-monitoring", "Tecnologia", ["GG-DB-ReadOnly"], None, True),
    ("svc-deploy-ci", "Tecnologia", ["GG-Prod-Deploy", "GG-Dev-Repo-Write"], None, True),
    ("svc-db-maintenance", "Tecnologia", ["GG-DB-Admins"], None, True),
    ("svc-etl-nightly", "Operações", ["GG-DB-ReadOnly"], None, True),
    ("svc-crm-sync", "Comercial", ["GG-CRM-Users"], None, True),
    ("svc-report-gen", "Financeiro", ["GG-Fin-Reports-Read"], None, True),
    ("svc-siem-forwarder", "Segurança da Informação", ["GG-Audit-Log-Read"], None, True),
    ("svc-payments-gw", "Operações", ["GG-Pay-Initiate"], None, True),
    ("svc-scan-vuln", "Segurança da Informação", ["GG-DB-ReadOnly"], None, True),
    ("svc-mail-relay", "Tecnologia", ["GG-Office365-E3"], None, True),
    ("svc-hr-export", "RH", ["GG-HR-Payroll"], 130, False),
    ("svc-batch-recon", "Financeiro", ["GG-Fin-AP-Create"], None, False),
    ("svc-legacy-app", "Tecnologia", ["GG-DB-Admins"], 210, False),
]


def _ascii(text: str) -> str:
    return unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()


def _quarter(d: date) -> str:
    return f"{d.year}-Q{(d.month - 1) // 3 + 1}"


# --------------------------------------------------------------------------- #
# Generator
# --------------------------------------------------------------------------- #
def generate(n_employees: int, seed: int, ref: date) -> dict[str, pd.DataFrame]:
    rng = np.random.default_rng(seed)

    def rint(lo: int, hi: int) -> int:
        """Random integer in [lo, hi)."""
        return int(rng.integers(lo, hi))

    def chance(p: float) -> bool:
        return bool(rng.random() < p)

    def pick(seq):
        return seq[rint(0, len(seq))]

    def sample(seq, k: int):
        """k distinct items from seq, in random order."""
        return [seq[int(i)] for i in rng.choice(len(seq), size=k, replace=False)]

    def days_ago(n: int) -> date:
        return ref - timedelta(days=int(n))

    # ---- HR records ------------------------------------------------------- #
    n_term = round(n_employees * 0.11)
    n_current = n_employees - n_term
    n_leave = max(2, round(n_current * 0.03))

    dept_names = list(DEPARTMENTS)
    probs = np.array([DEPARTMENTS[d][0] for d in dept_names], dtype=float)
    probs = probs / probs.sum()
    depts = [dept_names[int(i)] for i in rng.choice(len(dept_names), size=n_employees, p=probs)]

    statuses = ["active"] * n_current + ["terminated"] * n_term
    statuses = [statuses[int(i)] for i in rng.permutation(n_employees)]
    active_idx = [i for i, s in enumerate(statuses) if s == "active"]
    for i in sample(active_idx, n_leave):
        statuses[i] = "on_leave"

    used_account_ids: set[str] = set()  # only used for membership tests

    def make_account_id(first: str, last: str) -> str:
        base = _ascii(f"{first}.{last}").lower()
        candidate, n = base, 2
        while candidate in used_account_ids:
            candidate, n = f"{base}{n}", n + 1
        used_account_ids.add(candidate)
        return candidate

    employees: list[dict] = []
    for i in range(n_employees):
        first, last = pick(FIRST_NAMES), pick(LAST_NAMES)
        if statuses[i] == "terminated":
            hire, term = days_ago(rint(500, 365 * 10)), days_ago(rint(10, 420))
        else:
            hire, term = days_ago(rint(40, 365 * 14)), None
        employees.append({
            "employee_id": f"E{i + 1:05d}", "full_name": f"{first} {last}",
            "department": depts[i], "job_title": None, "manager_id": None,
            "hire_date": hire, "termination_date": term, "status": statuses[i],
            "_account_id": make_account_id(first, last),
        })

    # Managers: at least two active people per department review the others.
    managers: dict[str, list[str]] = {}
    for d in dept_names:
        pool = [e for e in employees if e["department"] == d and e["status"] == "active"]
        k = min(len(pool), max(2, math.ceil(0.1 * len(pool))))
        managers[d] = [pool[j]["employee_id"] for j in range(k)]
    mgr_ids = [m for d in dept_names for m in managers[d]]

    for e in employees:
        d = e["department"]
        if e["employee_id"] in managers[d]:
            e["job_title"] = f"Coordenador(a) de {d}"
            others = [m for m in managers[d] if m != e["employee_id"]]
            e["manager_id"] = pick(others) if others else None
        else:
            e["job_title"] = pick(DEPARTMENTS[d][1])
            e["manager_id"] = pick(managers[d]) if managers[d] else None

    account_of = {e["employee_id"]: e["_account_id"] for e in employees}
    status_of = {e["employee_id"]: e["status"] for e in employees}
    manager_of = {e["employee_id"]: e["manager_id"] for e in employees}

    # ---- Directory accounts ---------------------------------------------- #
    accounts: list[dict] = []
    for e in employees:
        accounts.append({
            "account_id": e["_account_id"], "employee_id": e["employee_id"],
            "display_name": e["full_name"], "department": e["department"],
            "account_type": "user", "enabled": True, "created_at": e["hire_date"],
            "last_logon": None, "disabled_at": None, "owner_employee_id": None,
        })
    by_emp = {a["employee_id"]: a for a in accounts}

    terminated = [e for e in employees if e["status"] == "terminated"]
    n_orphans = max(3, round(len(terminated) * 0.12))
    orphan_ids = [e["employee_id"] for e in sample(terminated, n_orphans)]
    lag_choices = [0, 1, 2, 3, 5, 9, 14]
    lag_probs = [0.35, 0.30, 0.15, 0.08, 0.06, 0.04, 0.02]

    for e in employees:
        a = by_emp[e["employee_id"]]
        if e["status"] == "active":
            a["last_logon"] = days_ago(min(int(rng.exponential(3)), 45))
        elif e["status"] == "on_leave":
            a["last_logon"] = days_ago(rint(35, 160))
        else:
            term = e["termination_date"]
            if e["employee_id"] in orphan_ids:
                # account left enabled; half of them were even used after leaving
                if chance(0.5):
                    a["last_logon"] = min(term + timedelta(days=rint(1, 26)), ref)
                else:
                    a["last_logon"] = term - timedelta(days=rint(0, 6))
            else:
                lag = int(rng.choice(lag_choices, p=lag_probs))
                a["enabled"] = False
                a["disabled_at"] = min(term + timedelta(days=lag), ref)
                a["last_logon"] = term - timedelta(days=rint(0, 4))

    # Dormant accounts (planted): active people with no logon for a long time.
    cand = [e for e in employees if e["status"] == "active" and e["employee_id"] not in mgr_ids]
    n_dormant = max(4, round(len(cand) * 0.05))
    priv_dept_cand = [e for e in cand if e["department"] in DEPT_PRIV_GROUP]
    first_two = sample(priv_dept_cand, 2)
    first_two_ids = [e["employee_id"] for e in first_two]
    rest = [e for e in cand if e["employee_id"] not in first_two_ids]
    dormant = first_two + sample(rest, n_dormant - 2)
    dormant_ids = [e["employee_id"] for e in dormant]
    for e in dormant:
        by_emp[e["employee_id"]]["last_logon"] = days_ago(rint(95, 320))

    # User accounts with no HR record (e.g. contractors).
    for k in range(1, 4):
        accounts.append({
            "account_id": f"tmp.consultor{k}", "employee_id": None,
            "display_name": f"Consultor Externo {k}", "department": pick(dept_names),
            "account_type": "user", "enabled": True, "created_at": days_ago(rint(120, 700)),
            "last_logon": days_ago(rint(0, 20)), "disabled_at": None,
            "owner_employee_id": None,
        })

    # Service accounts (no HR record, but should have an owner).
    for name, dept, _groups, dormant_days, has_owner in SERVICE_ACCOUNTS:
        accounts.append({
            "account_id": name, "employee_id": None, "display_name": name,
            "department": dept, "account_type": "service", "enabled": True,
            "created_at": days_ago(rint(400, 2000)),
            "last_logon": days_ago(dormant_days) if dormant_days else days_ago(rint(0, 3)),
            "disabled_at": None,
            "owner_employee_id": pick(managers[dept]) if has_owner else None,
        })

    acc_info = {a["account_id"]: a for a in accounts}

    # ---- Group memberships ------------------------------------------------ #
    holds: dict[str, list[str]] = {a["account_id"]: [] for a in accounts}
    partners: dict[str, list[str]] = {}
    for ga, gb, *_ in SOD_CONFLICTS:
        partners.setdefault(ga, []).append(gb)
        partners.setdefault(gb, []).append(ga)

    def grant(acc: str, grp: str) -> None:
        if grp not in holds[acc]:
            holds[acc].append(grp)

    def conflicts(acc: str, grp: str) -> bool:
        return any(x in holds[acc] for x in partners.get(grp, []))

    def grant_safe(acc: str, grp: str) -> None:
        if not conflicts(acc, grp):
            grant(acc, grp)

    # natural memberships (never create an SoD conflict by chance)
    for a in accounts:
        if a["account_type"] != "user":
            continue
        for g, p in BASE_GROUPS:
            if chance(p):
                grant(a["account_id"], g)
        if a["employee_id"] is None:
            continue
        for g, p in DEPT_GROUPS.get(a["department"], []):
            if chance(p) and not conflicts(a["account_id"], g):
                grant(a["account_id"], g)
    for name, _dept, groups_, _d, _o in SERVICE_ACCOUNTS:
        for g in groups_:
            grant(name, g)
    grant("tmp.consultor1", "GG-DB-ReadOnly")

    # privileged access kept by orphan and dormant accounts
    for emp_id in orphan_ids + first_two_ids:
        g = DEPT_PRIV_GROUP.get(acc_info[account_of[emp_id]]["department"])
        if g:
            grant_safe(account_of[emp_id], g)

    # ---- Planted anomalies ------------------------------------------------ #
    planted: list[tuple[str, str]] = []
    used_emps: list[str] = []
    eligible = [e for e in cand if e["employee_id"] not in dormant_ids]
    scale = n_employees / 400

    def plant(acc: str, grp: str) -> None:
        grant(acc, grp)
        planted.append((acc, grp))

    # 1) segregation-of-duties conflicts
    for (ga, gb, *_), base in zip(SOD_CONFLICTS, [4, 3, 2, 1]):
        pool = [e for e in eligible
                if e["department"] == GROUP_OWNER[ga] and e["employee_id"] not in used_emps]
        if not pool:
            continue
        for e in sample(pool, min(len(pool), max(1, round(base * scale)))):
            plant(account_of[e["employee_id"]], ga)
            plant(account_of[e["employee_id"]], gb)
            used_emps.append(e["employee_id"])

    # 2) privileged groups owned by another department (privilege creep)
    cross_groups = ["GG-Fin-AP-Approve", "GG-DB-Admins", "GG-Pay-Approve",
                    "GG-Server-Admins", "GG-HR-Payroll", "GG-Prod-Deploy"]
    for j in range(max(3, round(0.02 * n_employees))):
        g = cross_groups[j % len(cross_groups)]
        pool = [e for e in eligible
                if e["department"] != GROUP_OWNER[g] and e["employee_id"] not in used_emps]
        e = pick(pool)
        plant(account_of[e["employee_id"]], g)
        used_emps.append(e["employee_id"])

    # 3) accounts accumulating many privileged groups
    excess_sets = [
        ["GG-Server-Admins", "GG-Prod-Deploy", "GG-SIEM-Analysts", "GG-IAM-Admins"],
        ["GG-Server-Admins", "GG-Prod-Deploy", "GG-SIEM-Analysts"],
        ["GG-DB-Admins", "GG-Server-Admins", "GG-SIEM-Analysts"],
    ]
    tech_pool = [e for e in eligible
                 if e["department"] == "Tecnologia" and e["employee_id"] not in used_emps]
    for e, groups_ in zip(sample(tech_pool, len(excess_sets)), excess_sets):
        acc = account_of[e["employee_id"]]
        for g in groups_:
            if not conflicts(acc, g):
                plant(acc, g)
        used_emps.append(e["employee_id"])

    # ---- Membership rows -------------------------------------------------- #
    membership_rows: list[dict] = []
    for a in accounts:
        approvers = [m for m in managers.get(a["department"], [])
                     if account_of[m] != a["account_id"]]  # nobody approves their own access
        span = max((ref - a["created_at"]).days, 1)
        for g in holds[a["account_id"]]:
            membership_rows.append({
                "account_id": a["account_id"], "group_id": g,
                "granted_at": a["created_at"] + timedelta(days=rint(0, span)),
                "granted_by": account_of[pick(approvers)] if approvers else None,
            })

    # ---- Access reviews of privileged memberships ------------------------- #
    planted_set = set(planted)  # membership tests only
    reviews: list[dict] = []

    def add_review(acc, grp, reviewer, opened, due, decision, decided):
        reviews.append({
            "review_id": f"REV-{len(reviews) + 1:05d}", "account_id": acc, "group_id": grp,
            "reviewer_id": reviewer, "cycle": _quarter(opened), "opened_at": opened,
            "due_date": due, "decision": decision, "decided_at": decided,
        })

    for m in membership_rows:
        if GROUP_LEVEL[m["group_id"]] not in PRIVILEGED_LEVELS:
            continue
        a = acc_info[m["account_id"]]
        if a["account_type"] == "user":
            if a["employee_id"] is None or status_of[a["employee_id"]] == "terminated":
                continue  # nobody reviews accounts outside the HR population
            mgr = manager_of[a["employee_id"]]
            reviewer = account_of[mgr] if mgr else None
        else:
            owner = a["owner_employee_id"]
            reviewer = account_of[owner] if owner else None
        if reviewer is None:
            continue  # no reviewer -> never reviewed (picked up by rule R06)

        key = (m["account_id"], m["group_id"])
        # previous cycle: 90% reviewed
        opened = days_ago(150)
        if chance(0.90):
            revoked = chance(0.07) and key not in planted_set
            add_review(*key, reviewer, opened, days_ago(120),
                       "revoked" if revoked else "approved",
                       opened + timedelta(days=rint(4, 28)))
        # current cycle: roughly half done, some already overdue
        opened = days_ago(60)
        due = ref + timedelta(days=int(rng.choice([-30, -10, 15], p=[0.4, 0.2, 0.4])))
        if chance(0.55):
            revoked = chance(0.05) and key not in planted_set
            decided = min(opened + timedelta(days=rint(3, 45)), ref - timedelta(days=1))
            add_review(*key, reviewer, opened, due, "revoked" if revoked else "approved", decided)
        else:
            add_review(*key, reviewer, opened, due, "pending", None)

    # 3 approved reviews become "revoked but still a member" (rule R07)
    approved_idx = [i for i, r in enumerate(reviews)
                    if r["decision"] == "approved"
                    and (r["account_id"], r["group_id"]) not in planted_set]
    keep_keys = []
    for i in sample(approved_idx, min(3, len(approved_idx))):
        reviews[i]["decision"] = "revoked"
        keep_keys.append((reviews[i]["account_id"], reviews[i]["group_id"]))

    # every other revocation was actually executed: remove the membership
    removed = [(r["account_id"], r["group_id"]) for r in reviews
               if r["decision"] == "revoked" and (r["account_id"], r["group_id"]) not in keep_keys]
    membership_rows = [m for m in membership_rows
                       if (m["account_id"], m["group_id"]) not in removed]

    # ---- DataFrames ------------------------------------------------------- #
    def frame(rows, date_cols=()):
        df = pd.DataFrame(rows)
        for c in date_cols:
            df[c] = pd.to_datetime(df[c])
        return df

    hr_cols = ["employee_id", "full_name", "department", "job_title", "manager_id",
               "hire_date", "termination_date", "status"]
    return {
        "employees": frame([{c: e[c] for c in hr_cols} for e in employees],
                           ["hire_date", "termination_date"]),
        "accounts": frame(accounts, ["created_at", "last_logon", "disabled_at"]),
        "groups": pd.DataFrame(GROUPS, columns=["group_id", "description",
                                                "privilege_level", "owner_department"]),
        "memberships": frame(membership_rows, ["granted_at"]),
        "reviews": frame(reviews, ["opened_at", "due_date", "decided_at"]),
    }


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    p = argparse.ArgumentParser(description="Generate the synthetic IAM dataset.")
    p.add_argument("--employees", type=int, default=400, help="total HR records (min 100)")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--ref-date", default=None, help="YYYY-MM-DD (default: today)")
    p.add_argument("--out", default=str(root / "data"))
    args = p.parse_args()
    if args.employees < 100:
        p.error("--employees must be at least 100")

    ref = date.fromisoformat(args.ref_date) if args.ref_date else date.today()
    tables = generate(args.employees, args.seed, ref)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, df in tables.items():
        df.to_csv(out / f"{name}.csv", index=False, date_format="%Y-%m-%d")

    meta = {
        "synthetic": True,
        "note": "Todos os dados são fictícios e gerados por src/generate_data.py.",
        "seed": args.seed,
        "reference_date": ref.isoformat(),
        "rows": {k: int(len(v)) for k, v in tables.items()},
    }
    (out / "metadata.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n",
                                       encoding="utf-8")
    print(f"Dados sintéticos gerados em {out} (referência: {ref.isoformat()})")
    for k, v in meta["rows"].items():
        print(f"  {k:<12} {v:>5} linhas")


if __name__ == "__main__":
    main()
