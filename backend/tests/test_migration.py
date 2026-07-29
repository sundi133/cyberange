import sqlite3
import tempfile
import unittest
from pathlib import Path

from cyberrange.db import Database
from cyberrange.service import CyberRangeService

# The pre-migration shape of the detections table, as shipped by the first
# release: no rule_id / basis / severity / detail.
_OLD_DETECTIONS = """
CREATE TABLE detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    exercise_id TEXT NOT NULL,
    rule_version TEXT,
    technique_id TEXT,
    verdict TEXT,
    latency_s REAL,
    fp_context TEXT,
    ts_utc TEXT NOT NULL
);
"""


class SchemaMigrationTest(unittest.TestCase):
    """A database created by an older build must be upgraded in place.

    Regression test: `CREATE TABLE IF NOT EXISTS` does not add columns to an
    existing table, so recording a detection failed with
    "table detections has no column named rule_id".
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "old.db"
        conn = sqlite3.connect(self.path)
        conn.executescript(_OLD_DETECTIONS)
        conn.commit()
        conn.close()

    def tearDown(self):
        self.tmp.cleanup()

    def test_old_database_is_migrated_on_open(self):
        before = self._columns()
        self.assertNotIn("rule_id", before)

        Database(self.path)  # opening runs the migration

        after = self._columns()
        for col in ("rule_id", "basis", "severity", "detail"):
            self.assertIn(col, after, f"{col} was not added by the migration")

    def test_detection_can_be_recorded_after_migration(self):
        svc = CyberRangeService(Database(self.path))
        rng = svc.create_range("i", "instructor", "CR-PHISH-001")
        for a in ("preflight", "provision", "seed", "ready"):
            svc.lifecycle_action("i", "instructor", rng["id"], a)
        ex = svc.start_exercise("i", "instructor", rng["id"])["id"]
        # This is the call that used to raise OperationalError.
        svc.record_detection("i", "instructor", ex, technique_id="T1566",
                             verdict="detected", rule_version="v1",
                             rule_id="DR-TEST", basis="log", severity="high")
        dets = svc.list_detections(ex)
        self.assertEqual(dets[-1]["rule_id"], "DR-TEST")

    def test_migration_is_idempotent(self):
        Database(self.path)
        Database(self.path)  # second open must not fail
        self.assertIn("rule_id", self._columns())

    def _columns(self) -> set:
        conn = sqlite3.connect(self.path)
        cols = {r[1] for r in conn.execute("PRAGMA table_info(detections)")}
        conn.close()
        return cols


if __name__ == "__main__":
    unittest.main()
