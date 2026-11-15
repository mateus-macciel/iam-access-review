"""Shared policy constants: severity model, privileged levels and SoD conflicts.

Keeping the policy in one place means the synthetic-data generator and the
detection rules can never drift apart.
"""
from __future__ import annotations

# Points added to an account's risk score for each finding.
SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# Groups at these privilege levels are treated as "privileged access".
PRIVILEGED_LEVELS = ("high", "critical")

# Segregation of duties (SoD): pairs of groups that must not be held by the
# same account.  (group_a, group_b, severity, why it matters)
SOD_CONFLICTS = [
    (
        "GG-Fin-AP-Create",
        "GG-Fin-AP-Approve",
        "high",
        "Criação e aprovação de contas a pagar pela mesma conta",
    ),
    (
        "GG-Pay-Initiate",
        "GG-Pay-Approve",
        "critical",
        "Iniciação e aprovação de pagamentos pela mesma conta",
    ),
    (
        "GG-Prod-Deploy",
        "GG-DB-Admins",
        "high",
        "Deploy em produção e administração de banco de dados pela mesma conta",
    ),
    (
        "GG-IAM-Admins",
        "GG-Audit-Log-Read",
        "high",
        "Administração de identidades e leitura dos logs de auditoria (auditoria dos próprios atos)",
    ),
]
