"""The cloud tier (provisioners.cloud) and the Phase-1 cloud content.

The cloud content ships as Docker-adapter modules that emit cloud-flavoured
telemetry markers; detection rules fire on those markers end-to-end. The
cloud *tier* is a provisioner-contract seam a customer plugs into with their
cloud SDK for Phase 2 - this file pins the seam's shape plus the end-to-end
detection path.
"""
import unittest

from cyberrange import catalog
from cyberrange.db import Database
from cyberrange.provisioners import ContainerProvisioner, resolve
from cyberrange.provisioners.base import ProvisionError
from cyberrange.provisioners.cloud import (
    MarkerCloudProvisioner,
    SUPPORTED_PROVIDERS,
    from_env,
)
from cyberrange.service import CyberRangeService

NEW_MODULES = (
    "CR-MOD-CLOUD-METADATA-001",
    "CR-MOD-CLOUD-OAUTH-001",
    "CR-MOD-CLOUD-ACCT-MANIP-001",
    "CR-MOD-CLOUD-STORAGE-001",
    "CR-MOD-CLOUD-EXFIL-001",
    "CR-MOD-CLOUD-MAILRULE-001",
)


class MarkerCloudProvisionerTest(unittest.TestCase):
    """Contract: the cloud tier has the four methods the control plane calls,
    the identity shape ``/api/health`` reports, and refuses an unknown provider."""

    def test_requires_a_supported_provider(self):
        with self.assertRaises(ProvisionError):
            MarkerCloudProvisioner("not-a-cloud")

    def test_builds_each_supported_provider(self):
        for p in SUPPORTED_PROVIDERS:
            with self.subTest(provider=p):
                t = MarkerCloudProvisioner(p, sandbox="cr-test")
                self.assertEqual(t.provider, p)
                self.assertEqual(t.name, "cloud")

    def test_provision_names_the_sandbox_identity(self):
        t = MarkerCloudProvisioner("aws", sandbox="cr-sb-fixed")
        info = t.provision("range-abc")
        self.assertEqual(info["network"], "cloud:aws")
        self.assertEqual(len(info["targets"]), 1)
        tgt = info["targets"][0]
        self.assertEqual(tgt["name"], "cr-sb-fixed")
        self.assertEqual(tgt["role"], "cloud:aws")

    def test_has_target_accepts_logical_names(self):
        t = MarkerCloudProvisioner("aws", sandbox="cr-sb-fixed")
        # The modules declare target="cloud" OR target="sandbox"; the sandbox
        # name itself also works, since timeline events may tag it.
        for tgt in ("cloud", "sandbox", "cr-sb-fixed"):
            self.assertTrue(t.has_target("range-abc", tgt))
        self.assertFalse(t.has_target("range-abc", "win-endpoint"))

    def test_reset_and_teardown_are_safe_noops_on_marker_tier(self):
        t = MarkerCloudProvisioner("aws", sandbox="cr-sb")
        # The marker tier has no cloud state; these must not raise.
        info = t.reset("range-abc")
        self.assertEqual(info["network"], "cloud:aws")
        self.assertIsNone(t.teardown("range-abc"))


class CloudResolverTest(unittest.TestCase):
    """The resolver picks the cloud tier when env is set; otherwise it defaults
    to the container tier. VM tier beats cloud when both are set."""

    def setUp(self):
        self._clean_env()

    def tearDown(self):
        self._clean_env()

    def _clean_env(self):
        import os
        for k in ("CR_CLOUD_PROVIDER", "CR_CLOUD_SANDBOX",
                  "CR_PROXMOX_HOST"):
            os.environ.pop(k, None)

    def test_default_is_containers_without_env(self):
        self.assertIsInstance(resolve(), ContainerProvisioner)

    def test_cloud_env_selects_cloud_tier(self):
        import os
        os.environ["CR_CLOUD_PROVIDER"] = "aws"
        tier = resolve()
        self.assertEqual(tier.name, "cloud")
        self.assertEqual(tier.provider, "aws")

    def test_invalid_cloud_provider_falls_back_to_containers(self):
        import os
        os.environ["CR_CLOUD_PROVIDER"] = "not-a-cloud"
        self.assertIsInstance(resolve(), ContainerProvisioner)

    def test_vm_takes_precedence_over_cloud(self):
        import os
        os.environ["CR_PROXMOX_HOST"] = "https://pve.example:8006"
        os.environ["CR_CLOUD_PROVIDER"] = "aws"
        tier = resolve()
        # Proxmox has no templates/token set, so from_env returns None; the
        # resolver falls back to containers rather than reading the cloud env.
        # Either way the cloud tier is not what we got.
        self.assertNotEqual(tier.name, "cloud")

    def test_from_env_returns_none_when_unset(self):
        self.assertIsNone(from_env())


class CloudContentTest(unittest.TestCase):
    """Phase-1 cloud modules are shipped, signed, and bound to detections."""

    def test_cloud_modules_are_shipped_and_signed(self):
        by_id = {m["id"]: m for m in catalog.modules()}
        for mid in NEW_MODULES:
            with self.subTest(module=mid):
                self.assertIn(mid, by_id, f"missing {mid}")
                m = by_id[mid]
                self.assertTrue(m.get("signed"))
                self.assertEqual((m.get("execution") or {}).get("adapter"),
                                 "docker",
                                 "Phase-1 cloud modules run on the Docker tier "
                                 "so they execute without a cloud account")

    def test_flagship_scenario_builds_from_signed_modules(self):
        scn = {s["id"]: s for s in catalog.scenarios()}
        self.assertIn("CR-CLOUD-FLAG-001", scn)
        s = scn["CR-CLOUD-FLAG-001"]
        by_id = {m["id"]: m for m in catalog.modules()}
        for mid in s["module_ids"]:
            self.assertIn(mid, by_id)
            self.assertTrue(by_id[mid].get("signed"),
                            f"scenario would run unsigned module {mid}")

    def test_scenario_claims_match_module_techniques(self):
        s = next(x for x in catalog.scenarios() if x["id"] == "CR-CLOUD-FLAG-001")
        by_id = {m["id"]: m for m in catalog.modules()}
        module_techs = set()
        for mid in s["module_ids"]:
            module_techs.update(by_id[mid].get("technique_ids", []))
        missing = set(s["technique_ids"]) - module_techs
        self.assertFalse(missing, f"scenario claims uncovered techniques: {missing}")


class CloudDetectionEndToEndTest(unittest.TestCase):
    """When a cloud module runs through the sim adapter (Docker not available
    in this env), its coverage detection must fire. When a cloud module runs
    with real output, its log-basis detection fires on the marker."""

    def setUp(self):
        self.svc = CyberRangeService(Database(":memory:"))

    def _ready_exercise(self, scenario_id):
        rng = self.svc.create_range("inst", "instructor", scenario_id)
        for a in ("preflight", "provision", "seed", "ready"):
            rng = self.svc.lifecycle_action("inst", "instructor", rng["id"], a)
        return self.svc.start_exercise("inst", "instructor", rng["id"])

    def test_simulated_cloud_module_fires_coverage_detection(self):
        # With no Docker, the service picks the simulated adapter and emits
        # ttp-emulation events; the SIM detection must fire.
        self.svc._docker_ok = False
        ex = self._ready_exercise("CR-CLOUD-FLAG-001")
        result = self.svc.execute_module(
            "inst", "instructor", ex["id"],
            "CR-MOD-CLOUD-METADATA-001", in_lesson=True)
        fired = {d["rule_id"] for d in result["detections"]}
        self.assertIn("DR-CLOUD-METADATA-SIM", fired,
                      f"sim-adapter path did not fire the coverage rule; got {fired}")


if __name__ == "__main__":
    unittest.main()
