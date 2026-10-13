"""The reviewer sign workflow (scripts/sign_modules.py).

Imports land as ``signed: false``; the service refuses to execute them. This
tool is how a reviewer flips the gate on a curated batch. These tests pin:

- the sign-one path (unsigned -> signed, class recorded, log entry written)
- the batch path (manifest -> many modules signed in one go)
- the safety rails: PROHIBITED cannot be signed; S2 needs acknowledgement;
  missing technique_ids/platform refused; unknown IDs refused
- audit integrity: unsign keeps the signing-log history, flips the gate off
- idempotency: signing an already-signed module is a no-op

The tool is a standalone CLI so these tests load it as a module and call its
functions through a namespaced Args; no subprocess shell-outs.
"""
import importlib.util
import json
import pathlib
import tempfile
import types
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "sign_modules.py"


def _load_tool() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("sign_modules", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _staged(mod_id, *, platform="linux", techs=("T1059",),
            risk_flags=("download",), signed=False, class_="S1",
            elevation=False, prohibited=False):
    """Mint a staged module with the same shape import_atomics writes."""
    sc = "PROHIBITED" if prohibited else class_
    return {
        "id": mod_id,
        "name": f"{mod_id} test module",
        "version": "0.1.0",
        "technique_ids": list(techs),
        "tactic": "imported",
        "platform": platform,
        "safety_class": sc,
        "approval": "PENDING REVIEW - imported, not yet classified",
        "preconditions": ["Imported content - review before enabling"],
        "timeout_seconds": 120,
        "signed": signed,
        "execution": {"adapter": "docker", "image": "alpine:3.19",
                      "network": "none", "cmd": ["sh", "-c", "id"]},
        "_import": {
            "source": "atomic-red-team",
            "attack_technique": techs[0],
            "executor": "sh",
            "elevation_required": elevation,
            "risk_flags": list(risk_flags),
            "suggested_class": "S2" if (elevation or risk_flags) else "S1",
        },
    }


class _Args(types.SimpleNamespace):
    """Stand-in for argparse.Namespace; defaults are set per-test."""


class SignModulesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.staged = pathlib.Path(self.tmp.name) / "modules.staged.json"
        self.log = pathlib.Path(self.tmp.name) / "_signing_log.jsonl"
        self.staged.write_text(json.dumps([
            _staged("CR-ATOMIC-T1059-01"),                        # ordinary
            _staged("CR-ATOMIC-T1548-01", risk_flags=["privilege"]),  # needs S2 ack
            _staged("CR-ATOMIC-X-PROHIB", prohibited=True),       # must refuse
            _staged("CR-ATOMIC-X-NOPLAT", platform=None),         # must refuse
        ]))
        # Point the tool at the temp fixtures without monkeying with cwd.
        self.tool = _load_tool()
        self.tool.STAGED = self.staged
        self.tool.LOG = self.log

    def tearDown(self):
        self.tmp.cleanup()

    # ---- single sign ------------------------------------------------------
    def test_signs_a_pending_module_and_logs_it(self):
        rc = self.tool.cmd_sign(_Args(
            ids=["CR-ATOMIC-T1059-01"], reviewer="alice",
            cls="S1", notes="shell interpreter, benign",
            acknowledge_s2=False, dry_run=False))
        self.assertEqual(rc, 0)

        mods = json.loads(self.staged.read_text())
        m = next(m for m in mods if m["id"] == "CR-ATOMIC-T1059-01")
        self.assertTrue(m["signed"])
        self.assertEqual(m["safety_class"], "S1")
        self.assertEqual(m["approval"], "Security content reviewer")
        self.assertEqual(m["_review"]["reviewer"], "alice")
        self.assertEqual(m["_review"]["signed_class"], "S1")

        log = [json.loads(line) for line in self.log.read_text().splitlines() if line.strip()]
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["action"], "sign")
        self.assertEqual(log[0]["module_id"], "CR-ATOMIC-T1059-01")
        self.assertEqual(log[0]["reviewer"], "alice")

    def test_already_signed_is_noop_no_duplicate_log(self):
        a = _Args(ids=["CR-ATOMIC-T1059-01"], reviewer="alice",
                  cls="S1", notes=None, acknowledge_s2=False, dry_run=False)
        self.tool.cmd_sign(a)
        self.tool.cmd_sign(a)              # second pass
        log = [l for l in self.log.read_text().splitlines() if l.strip()]
        self.assertEqual(len(log), 1, "double-sign must not produce a second log entry")

    def test_dry_run_does_not_write(self):
        self.tool.cmd_sign(_Args(
            ids=["CR-ATOMIC-T1059-01"], reviewer="alice",
            cls="S1", notes=None, acknowledge_s2=False, dry_run=True))
        mods = json.loads(self.staged.read_text())
        m = next(m for m in mods if m["id"] == "CR-ATOMIC-T1059-01")
        self.assertFalse(m["signed"], "--dry-run must not write")
        self.assertFalse(self.log.exists(),
                         "--dry-run must not append a 'sign' log entry")

    # ---- safety rails -----------------------------------------------------
    def test_prohibited_cannot_be_signed(self):
        rc = self.tool.cmd_sign(_Args(
            ids=["CR-ATOMIC-X-PROHIB"], reviewer="alice",
            cls="S2", notes=None, acknowledge_s2=True, dry_run=False))
        self.assertEqual(rc, 1)
        m = next(x for x in json.loads(self.staged.read_text())
                 if x["id"] == "CR-ATOMIC-X-PROHIB")
        self.assertFalse(m["signed"])

    def test_s2_requires_acknowledgement(self):
        rc = self.tool.cmd_sign(_Args(
            ids=["CR-ATOMIC-T1548-01"], reviewer="alice",
            cls="S2", notes=None, acknowledge_s2=False, dry_run=False))
        self.assertEqual(rc, 1, "S2 must refuse without --acknowledge-s2")
        m = next(x for x in json.loads(self.staged.read_text())
                 if x["id"] == "CR-ATOMIC-T1548-01")
        self.assertFalse(m["signed"])

    def test_s2_with_acknowledgement_signs(self):
        rc = self.tool.cmd_sign(_Args(
            ids=["CR-ATOMIC-T1548-01"], reviewer="alice",
            cls="S2", notes="high-impact; policy approved",
            acknowledge_s2=True, dry_run=False))
        self.assertEqual(rc, 0)
        m = next(x for x in json.loads(self.staged.read_text())
                 if x["id"] == "CR-ATOMIC-T1548-01")
        self.assertTrue(m["signed"])
        self.assertEqual(m["safety_class"], "S2")

    def test_missing_platform_refused(self):
        rc = self.tool.cmd_sign(_Args(
            ids=["CR-ATOMIC-X-NOPLAT"], reviewer="alice",
            cls="S1", notes=None, acknowledge_s2=False, dry_run=False))
        self.assertEqual(rc, 1)

    def test_unknown_id_refused(self):
        rc = self.tool.cmd_sign(_Args(
            ids=["CR-ATOMIC-NO-SUCH"], reviewer="alice",
            cls="S1", notes=None, acknowledge_s2=False, dry_run=False))
        self.assertEqual(rc, 1)

    # ---- batch ------------------------------------------------------------
    def test_batch_signs_many_in_one_call(self):
        batch = pathlib.Path(self.tmp.name) / "b.json"
        batch.write_text(json.dumps({
            "reviewer": "alice",
            "notes": "Q4 depth sprint",
            "modules": [
                {"id": "CR-ATOMIC-T1059-01", "class": "S1"},
                {"id": "CR-ATOMIC-T1548-01", "class": "S2",
                 "notes": "privilege path, policy approved"},
            ],
        }))
        rc = self.tool.cmd_batch(_Args(
            batch=str(batch), reviewer=None,
            acknowledge_s2=True, dry_run=False))
        self.assertEqual(rc, 0)
        mods = {m["id"]: m for m in json.loads(self.staged.read_text())}
        self.assertTrue(mods["CR-ATOMIC-T1059-01"]["signed"])
        self.assertTrue(mods["CR-ATOMIC-T1548-01"]["signed"])
        self.assertEqual(mods["CR-ATOMIC-T1548-01"]["safety_class"], "S2")

    def test_batch_cli_reviewer_overrides_manifest(self):
        batch = pathlib.Path(self.tmp.name) / "b.json"
        batch.write_text(json.dumps({
            "reviewer": "manifest-default",
            "modules": [{"id": "CR-ATOMIC-T1059-01", "class": "S1"}],
        }))
        self.tool.cmd_batch(_Args(
            batch=str(batch), reviewer="cli-wins",
            acknowledge_s2=False, dry_run=False))
        log = [json.loads(l) for l in self.log.read_text().splitlines() if l.strip()]
        self.assertEqual(log[0]["reviewer"], "cli-wins",
                         "a reviewer passed on the CLI must override the manifest")

    def test_batch_refuses_placeholder_reviewer(self):
        batch = pathlib.Path(self.tmp.name) / "b.json"
        batch.write_text(json.dumps({
            "reviewer": "REPLACE-WITH-YOUR-REVIEWER-IDENTITY",
            "modules": [{"id": "CR-ATOMIC-T1059-01", "class": "S1"}],
        }))
        rc = self.tool.cmd_batch(_Args(
            batch=str(batch), reviewer=None,
            acknowledge_s2=False, dry_run=False))
        self.assertEqual(rc, 2, "placeholder reviewer must refuse the whole batch")
        m = next(x for x in json.loads(self.staged.read_text())
                 if x["id"] == "CR-ATOMIC-T1059-01")
        self.assertFalse(m["signed"])

    def test_batch_partial_refusal_does_not_wipe_others(self):
        batch = pathlib.Path(self.tmp.name) / "b.json"
        batch.write_text(json.dumps([
            {"id": "CR-ATOMIC-T1059-01", "class": "S1"},
            {"id": "CR-ATOMIC-X-PROHIB", "class": "S2"},     # must refuse
        ]))
        rc = self.tool.cmd_batch(_Args(
            batch=str(batch), reviewer="alice",
            acknowledge_s2=True, dry_run=False))
        self.assertEqual(rc, 1, "overall exit code must flag the refusal")
        mods = {m["id"]: m for m in json.loads(self.staged.read_text())}
        self.assertTrue(mods["CR-ATOMIC-T1059-01"]["signed"],
                        "a partial failure must not block the valid signings")
        self.assertFalse(mods["CR-ATOMIC-X-PROHIB"]["signed"])

    # ---- unsign / audit ---------------------------------------------------
    def test_unsign_flips_gate_off_and_records_the_event(self):
        self.tool.cmd_sign(_Args(
            ids=["CR-ATOMIC-T1059-01"], reviewer="alice",
            cls="S1", notes=None, acknowledge_s2=False, dry_run=False))
        rc = self.tool.cmd_unsign(_Args(
            id="CR-ATOMIC-T1059-01", reviewer="alice",
            reason="rotation review"))
        self.assertEqual(rc, 0)
        m = next(x for x in json.loads(self.staged.read_text())
                 if x["id"] == "CR-ATOMIC-T1059-01")
        self.assertFalse(m["signed"])
        self.assertNotIn("_review", m)
        actions = [json.loads(l)["action"]
                   for l in self.log.read_text().splitlines() if l.strip()]
        self.assertEqual(actions, ["sign", "unsign"],
                         "both events must be in the log, oldest first")


class SignModulesCatalogIntegrationTest(unittest.TestCase):
    """A signed staged module is executable; an unsigned one is not."""

    def setUp(self):
        from cyberrange import catalog
        self._orig_seed = catalog.SEED_DIR
        self.tmp = tempfile.TemporaryDirectory()
        self.seed = pathlib.Path(self.tmp.name)
        # Copy curated seed files so the real catalog APIs work.
        for f in self._orig_seed.glob("*.json"):
            (self.seed / f.name).write_text(f.read_text())
        catalog.SEED_DIR = self.seed
        catalog._load.cache_clear()
        catalog._staged_scenarios.cache_clear()
        catalog._staged_modules.cache_clear()
        self.catalog = catalog
        self.tool = _load_tool()
        self.tool.STAGED = self.seed / "modules.staged.json"
        self.tool.LOG = self.seed / "_signing_log.jsonl"
        self.tool.STAGED.write_text(json.dumps([
            _staged("CR-ATOMIC-INTEG-01"),
        ]))
        catalog._staged_modules.cache_clear()

    def tearDown(self):
        self.catalog.SEED_DIR = self._orig_seed
        self.catalog._load.cache_clear()
        self.catalog._staged_scenarios.cache_clear()
        self.catalog._staged_modules.cache_clear()
        self.tmp.cleanup()

    def test_signed_module_is_catalog_executable(self):
        # Before signing: the module is listed but unsigned.
        m = next(x for x in self.catalog.modules() if x["id"] == "CR-ATOMIC-INTEG-01")
        self.assertFalse(m["signed"])

        # Sign it.
        self.tool.cmd_sign(_Args(
            ids=["CR-ATOMIC-INTEG-01"], reviewer="alice",
            cls="S1", notes=None, acknowledge_s2=False, dry_run=False))

        # The catalog cache must be cleared to see the change on disk.
        self.catalog._staged_modules.cache_clear()
        m2 = next(x for x in self.catalog.modules() if x["id"] == "CR-ATOMIC-INTEG-01")
        self.assertTrue(m2["signed"],
                        "catalog must see the module as signed once the file is updated")


if __name__ == "__main__":
    unittest.main()
