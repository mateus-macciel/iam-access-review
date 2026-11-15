"""Unit tests for the detection rules, using tiny hand-made datasets.

Run with:  python -m unittest discover -s tests -v   (or: pytest)
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pandas as pd  # noqa: E402

from rules import (Config, Dataset, r01_orphan_accounts, r02_dormant_accounts,  # noqa: E402
                   r03_sod_conflicts, r04_cross_department_privilege,
                   r05_excessive_privileged_groups, r06_unreviewed_privileged_access,
                   r07_revoked_not_removed, r08_overdue_reviews, r09_late_deprovisioning,
                   r10_service_account_without_owner, run_all)

REF = pd.Timestamp("2026-11-13")
CFG = Config(reference_date=REF)


def d(days_ago):
    """Timestamp N days before the reference date."""
    return REF - pd.Timedelta(days=days_ago)


def emp(eid, status="active", dept="Tecnologia", term=None):
    return {"employee_id": eid, "full_name": eid, "department": dept, "job_title": "x",
            "manager_id": None, "hire_date": d(900), "termination_date": term, "status": status}


def acc(aid, eid=None, dept="Tecnologia", kind="user", enabled=True, last=5,
        disabled=None, owner=None):
    return {"account_id": aid, "employee_id": eid, "display_name": aid, "department": dept,
            "account_type": kind, "enabled": enabled, "created_at": d(800),
            "last_logon": None if last is None else d(last), "disabled_at": disabled,
            "owner_employee_id": owner}


def grp(gid, level="low", owner="Tecnologia"):
    return {"group_id": gid, "description": gid, "privilege_level": level,
            "owner_department": owner}


def mem(aid, gid):
    return {"account_id": aid, "group_id": gid, "granted_at": d(300), "granted_by": None}


def rev(aid, gid, decision, decided=None, due=None, reviewer="boss"):
    return {"review_id": f"R-{aid}-{gid}-{decision}", "account_id": aid, "group_id": gid,
            "reviewer_id": reviewer, "cycle": "2026-Q3", "opened_at": d(60),
            "due_date": due if due is not None else d(30), "decision": decision,
            "decided_at": decided}


def make_ds(employees=(), accounts=(), groups=(), memberships=(), reviews=()):
    def frame(rows, cols, dates):
        df = pd.DataFrame(list(rows), columns=cols)
        for c in dates:
            df[c] = pd.to_datetime(df[c])
        return df

    return Dataset(
        employees=frame(employees, ["employee_id", "full_name", "department", "job_title",
                                    "manager_id", "hire_date", "termination_date", "status"],
                        ["hire_date", "termination_date"]),
        accounts=frame(accounts, ["account_id", "employee_id", "display_name", "department",
                                  "account_type", "enabled", "created_at", "last_logon",
                                  "disabled_at", "owner_employee_id"],
                       ["created_at", "last_logon", "disabled_at"]),
        groups=frame(groups, ["group_id", "description", "privilege_level", "owner_department"], []),
        memberships=frame(memberships, ["account_id", "group_id", "granted_at", "granted_by"],
                          ["granted_at"]),
        reviews=frame(reviews, ["review_id", "account_id", "group_id", "reviewer_id", "cycle",
                                "opened_at", "due_date", "decision", "decided_at"],
                      ["opened_at", "due_date", "decided_at"]),
    )


class OrphanAccounts(unittest.TestCase):
    def test_terminated_person_with_enabled_account_is_flagged(self):
        ds = make_ds([emp("E1", "terminated", term=d(60))], [acc("a1", "E1", last=70)])
        out = r01_orphan_accounts(ds, CFG)
        self.assertEqual(out["account_id"].tolist(), ["a1"])
        self.assertEqual(out["severity"].tolist(), ["high"])

    def test_logon_after_termination_is_critical(self):
        ds = make_ds([emp("E1", "terminated", term=d(60))], [acc("a1", "E1", last=20)])
        self.assertEqual(r01_orphan_accounts(ds, CFG)["severity"].tolist(), ["critical"])

    def test_active_person_and_disabled_account_are_not_flagged(self):
        ds = make_ds([emp("E1"), emp("E2", "terminated", term=d(60))],
                     [acc("a1", "E1"), acc("a2", "E2", enabled=False, last=70, disabled=d(59))])
        self.assertTrue(r01_orphan_accounts(ds, CFG).empty)

    def test_user_account_without_hr_record_is_flagged(self):
        ds = make_ds([], [acc("tmp.1", None)])
        self.assertEqual(r01_orphan_accounts(ds, CFG)["account_id"].tolist(), ["tmp.1"])


class DormantAccounts(unittest.TestCase):
    def test_old_logon_is_flagged_and_privileged_raises_severity(self):
        ds = make_ds([emp("E1"), emp("E2")],
                     [acc("a1", "E1", last=200), acc("a2", "E2", last=200)],
                     [grp("G-ADM", "critical")], [mem("a2", "G-ADM")])
        out = r02_dormant_accounts(ds, CFG).set_index("account_id")
        self.assertEqual(out.loc["a1", "severity"], "medium")
        self.assertEqual(out.loc["a2", "severity"], "high")

    def test_recent_logon_and_people_on_leave_are_ignored(self):
        ds = make_ds([emp("E1"), emp("E2", "on_leave")],
                     [acc("a1", "E1", last=10), acc("a2", "E2", last=200)])
        self.assertTrue(r02_dormant_accounts(ds, CFG).empty)

    def test_threshold_is_configurable(self):
        ds = make_ds([emp("E1")], [acc("a1", "E1", last=50)])
        self.assertTrue(r02_dormant_accounts(ds, CFG).empty)
        strict = Config(reference_date=REF, dormant_days=30)
        self.assertEqual(len(r02_dormant_accounts(ds, strict)), 1)


class SegregationOfDuties(unittest.TestCase):
    def test_both_groups_of_a_conflicting_pair_are_flagged(self):
        ds = make_ds([emp("E1"), emp("E2")], [acc("a1", "E1"), acc("a2", "E2")],
                     memberships=[mem("a1", "GG-Pay-Initiate"), mem("a1", "GG-Pay-Approve"),
                                  mem("a2", "GG-Pay-Initiate")])
        out = r03_sod_conflicts(ds, CFG)
        self.assertEqual(out["account_id"].tolist(), ["a1"])
        self.assertEqual(out["severity"].tolist(), ["critical"])


class PrivilegedAccess(unittest.TestCase):
    def test_cross_department_privilege(self):
        ds = make_ds([emp("E1", dept="Atendimento"), emp("E2", dept="Financeiro")],
                     [acc("a1", "E1", dept="Atendimento"), acc("a2", "E2", dept="Financeiro")],
                     [grp("GG-Fin-AP-Approve", "high", "Financeiro")],
                     [mem("a1", "GG-Fin-AP-Approve"), mem("a2", "GG-Fin-AP-Approve")])
        self.assertEqual(r04_cross_department_privilege(ds, CFG)["account_id"].tolist(), ["a1"])

    def test_excessive_privileged_groups_threshold(self):
        groups = [grp(f"G{i}", "high") for i in range(4)]
        ds = make_ds([emp("E1"), emp("E2")], [acc("a1", "E1"), acc("a2", "E2")], groups,
                     [mem("a1", "G0"), mem("a1", "G1"), mem("a1", "G2"),
                      mem("a2", "G0"), mem("a2", "G1")])
        out = r05_excessive_privileged_groups(ds, CFG)
        self.assertEqual(out["account_id"].tolist(), ["a1"])
        self.assertEqual(out["severity"].tolist(), ["medium"])


class Reviews(unittest.TestCase):
    def setUp(self):
        self.base = dict(employees=[emp("E1")], accounts=[acc("a1", "E1")],
                         groups=[grp("G-ADM", "critical")], memberships=[mem("a1", "G-ADM")])

    def test_privileged_access_without_review_is_flagged(self):
        out = r06_unreviewed_privileged_access(make_ds(**self.base), CFG)
        self.assertEqual(out["severity"].tolist(), ["high"])

    def test_recent_completed_review_clears_it(self):
        ds = make_ds(**self.base, reviews=[rev("a1", "G-ADM", "approved", decided=d(30))])
        self.assertTrue(r06_unreviewed_privileged_access(ds, CFG).empty)

    def test_review_older_than_window_does_not_count(self):
        ds = make_ds(**self.base, reviews=[rev("a1", "G-ADM", "approved", decided=d(400))])
        self.assertEqual(len(r06_unreviewed_privileged_access(ds, CFG)), 1)

    def test_revoked_but_still_member(self):
        ds = make_ds(**self.base, reviews=[rev("a1", "G-ADM", "revoked", decided=d(20))])
        self.assertEqual(r07_revoked_not_removed(ds, CFG)["account_id"].tolist(), ["a1"])

    def test_revoked_and_removed_is_fine(self):
        base = dict(self.base, memberships=[])
        ds = make_ds(**base, reviews=[rev("a1", "G-ADM", "revoked", decided=d(20))])
        self.assertTrue(r07_revoked_not_removed(ds, CFG).empty)

    def test_overdue_pending_review_severity_grows_with_delay(self):
        ds = make_ds(**self.base, reviews=[
            rev("a1", "G-ADM", "pending", due=d(10)),
            rev("a1", "G-X", "pending", due=d(45)),
            rev("a1", "G-Y", "pending", due=REF + pd.Timedelta(days=5))])
        out = r08_overdue_reviews(ds, CFG).set_index("group_id")
        self.assertEqual(out.loc["G-ADM", "severity"], "low")
        self.assertEqual(out.loc["G-X", "severity"], "medium")
        self.assertNotIn("G-Y", out.index)


class Offboarding(unittest.TestCase):
    def test_late_deprovisioning_respects_sla(self):
        ds = make_ds(
            [emp("E1", "terminated", term=d(60)), emp("E2", "terminated", term=d(60))],
            [acc("a1", "E1", enabled=False, last=62, disabled=d(59)),   # 1 day: ok
             acc("a2", "E2", enabled=False, last=62, disabled=d(50))])  # 10 days: late
        out = r09_late_deprovisioning(ds, CFG)
        self.assertEqual(out["account_id"].tolist(), ["a2"])
        self.assertEqual(out["severity"].tolist(), ["medium"])


class ServiceAccounts(unittest.TestCase):
    def test_service_account_without_owner(self):
        ds = make_ds([emp("E1")],
                     [acc("svc-a", kind="service", owner=None),
                      acc("svc-b", kind="service", owner="E1")])
        self.assertEqual(r10_service_account_without_owner(ds, CFG)["account_id"].tolist(),
                         ["svc-a"])


class Orchestration(unittest.TestCase):
    def test_orphan_accounts_do_not_also_get_unreviewed_access_findings(self):
        ds = make_ds([emp("E1", "terminated", term=d(60))], [acc("a1", "E1", last=70)],
                     [grp("G-ADM", "critical")], [mem("a1", "G-ADM")])
        findings = run_all(ds, CFG)
        self.assertEqual(set(findings["rule_id"]), {"R01"})

    def test_findings_are_enriched_and_ranked(self):
        ds = make_ds([emp("E1", "terminated", term=d(60))], [acc("a1", "E1", last=20)])
        f = run_all(ds, CFG)
        self.assertEqual(f.loc[0, "finding_id"], "F0001")
        self.assertEqual(f.loc[0, "risk_points"], 4)
        self.assertIn("remediation", f.columns)


if __name__ == "__main__":
    unittest.main()
