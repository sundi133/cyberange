import io
import json
import unittest
import xml.dom.minidom
import zipfile

from cyberrange import catalog, reporting
from cyberrange.db import Database
from cyberrange.service import CyberRangeService


class ReportRenderTest(unittest.TestCase):
    def setUp(self):
        self.svc = CyberRangeService(Database(":memory:"))
        rng = self.svc.create_range("i", "instructor", "CR-PHISH-001")
        for a in ("preflight", "provision", "seed", "ready"):
            self.svc.lifecycle_action("i", "instructor", rng["id"], a)
        ex = self.svc.start_exercise("i", "instructor", rng["id"])
        self.svc.execute_module("i", "instructor", ex["id"], "CR-MOD-PHISH-001")
        self.svc.submit_evidence("blue", "blue", ex["id"], description="alert triaged")
        self.report = self.svc.build_report(ex["id"])

    def test_json_valid(self):
        data = json.loads(reporting.report_json(self.report))
        self.assertEqual(data["scenario"]["id"], "CR-PHISH-001")

    def test_csv_has_sections(self):
        csv_text = reporting.report_csv(self.report)
        self.assertIn("Phish to foothold", csv_text)
        self.assertIn("detections:", csv_text)
        self.assertIn("coverage", csv_text)

    def test_html_is_printable_report(self):
        h = reporting.report_html(self.report)
        self.assertIn("<!doctype html>", h.lower())
        self.assertIn("After-Action Report", h)
        self.assertIn(self.report["exercise_id"], h)

    def test_docx_is_valid_ooxml(self):
        blob = reporting.report_docx(self.report)
        z = zipfile.ZipFile(io.BytesIO(blob))
        self.assertIsNone(z.testzip())
        self.assertEqual(set(z.namelist()),
                         {"[Content_Types].xml", "_rels/.rels", "word/document.xml"})
        # document.xml must be well-formed XML
        xml.dom.minidom.parseString(z.read("word/document.xml"))
        self.assertIn(b"After-Action Report", z.read("word/document.xml"))


class GradebookCsvTest(unittest.TestCase):
    def test_gradebook_csv(self):
        svc = CyberRangeService(Database(":memory:"))
        c = svc.create_cohort("prof", "instructor", "CS101")
        svc.import_roster("prof", "instructor", c["id"], "alice,Alice")
        svc.create_assignment("prof", "instructor", c["id"], "CR-PHISH-001")
        gb = svc.gradebook("prof", "instructor", c["id"])
        csv_text = reporting.gradebook_csv(gb)
        self.assertIn("CS101", csv_text)
        self.assertIn("Alice", csv_text)
        self.assertIn("Student", csv_text)  # header


if __name__ == "__main__":
    unittest.main()
