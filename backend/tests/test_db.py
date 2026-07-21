import unittest

from cyberrange import db


class DsnDetectionTest(unittest.TestCase):
    def test_postgres_dsns(self):
        self.assertTrue(db.is_postgres_dsn("postgres://u:p@h:5432/db"))
        self.assertTrue(db.is_postgres_dsn("postgresql://u:p@h/db"))

    def test_non_postgres(self):
        self.assertFalse(db.is_postgres_dsn(":memory:"))
        self.assertFalse(db.is_postgres_dsn("/var/data/cyberrange.db"))
        self.assertFalse(db.is_postgres_dsn(None))


class SqlTranslationTest(unittest.TestCase):
    def test_placeholder_conversion(self):
        out = db._to_pg("SELECT * FROM t WHERE a=? AND b=?")
        self.assertEqual(out, "SELECT * FROM t WHERE a=%s AND b=%s")

    def test_insert_or_ignore_becomes_on_conflict(self):
        out = db._to_pg("INSERT OR IGNORE INTO cohort_members (a,b) VALUES (?,?)")
        self.assertNotIn("OR IGNORE", out)
        self.assertTrue(out.endswith("ON CONFLICT DO NOTHING"))
        self.assertIn("(%s,%s)", out)

    def test_plain_insert_unchanged_semantically(self):
        out = db._to_pg("INSERT INTO t (a) VALUES (?)")
        self.assertEqual(out, "INSERT INTO t (a) VALUES (%s)")
        self.assertNotIn("ON CONFLICT", out)


class SchemaTest(unittest.TestCase):
    def test_sqlite_schema_uses_autoincrement(self):
        s = db._schema_for("sqlite")
        self.assertIn("AUTOINCREMENT", s)
        self.assertNotIn("BIGSERIAL", s)

    def test_postgres_schema_uses_bigserial(self):
        s = db._schema_for("postgres")
        self.assertIn("BIGSERIAL", s)
        self.assertNotIn("AUTOINCREMENT", s)
        self.assertNotIn("{AUTOPK}", s)


class FactoryTest(unittest.TestCase):
    def test_connect_returns_sqlite_for_memory(self):
        d = db.connect(":memory:")
        self.assertIsInstance(d, db.Database)
        d.close()

    def test_execute_returning_id_on_sqlite(self):
        d = db.connect(":memory:")
        d.execute("INSERT INTO exercises (id, range_id, scenario_id, status) "
                  "VALUES (?,?,?,?)", ("ex1", "r1", "CR-PHISH-001", "running"))
        new_id = d.execute_returning_id(
            "INSERT INTO events (exercise_id, ts_utc, source, kind) VALUES (?,?,?,?)",
            ("ex1", "2026-01-01T00:00:00+00:00", "test", "unit"))
        self.assertIsInstance(new_id, int)
        self.assertGreaterEqual(new_id, 1)
        d.close()


if __name__ == "__main__":
    unittest.main()
