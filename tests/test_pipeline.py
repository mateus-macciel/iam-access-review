"""End-to-end checks: the generator is reproducible and exercises every rule."""
import sys
import unittest
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pandas as pd  # noqa: E402

from generate_data import generate  # noqa: E402
from rules import RULES, Config, Dataset, run_all  # noqa: E402

REF = date(2026, 11, 13)


class Pipeline(unittest.TestCase):
    def test_generator_is_reproducible(self):
        a, b = generate(200, 7, REF), generate(200, 7, REF)
        for name in a:
            pd.testing.assert_frame_equal(a[name], b[name])

    def test_different_seeds_give_different_data(self):
        a, b = generate(200, 1, REF), generate(200, 2, REF)
        self.assertFalse(a["accounts"]["account_id"].equals(b["accounts"]["account_id"]))

    def test_every_rule_fires_on_the_default_dataset(self):
        tables = generate(400, 42, REF)
        findings = run_all(Dataset(**tables), Config(reference_date=pd.Timestamp(REF)))
        self.assertEqual(set(findings["rule_id"]), set(RULES))

    def test_referential_integrity(self):
        t = generate(400, 42, REF)
        accounts = set(t["accounts"]["account_id"])
        groups = set(t["groups"]["group_id"])
        self.assertTrue(set(t["memberships"]["account_id"]) <= accounts)
        self.assertTrue(set(t["memberships"]["group_id"]) <= groups)
        self.assertTrue(set(t["reviews"]["account_id"]) <= accounts)
        self.assertEqual(t["accounts"]["account_id"].is_unique, True)


if __name__ == "__main__":
    unittest.main()
