import unittest
from tools.pipeline import run
class PipelineTest(unittest.TestCase):
    def test_detection_and_measurement(self):
        events=[
            {"id":"1","host":"s","timestamp":"2026-10-22T10:00:00Z","kind":"http_anomaly"},
            {"id":"2","host":"s","timestamp":"2026-10-22T10:00:30Z","kind":"web_child_process"},
            {"id":"3","host":"b","timestamp":"2026-10-22T10:00:00Z","kind":"http_anomaly"}]
        labels=[{"id":"s","label":"suspicious"},{"id":"b","label":"benign"}]
        report=run(events,labels)
        self.assertEqual(report["event_count"],3)
        self.assertEqual(report["evaluation"]["tp"],1)
        self.assertEqual(report["evaluation"]["tn"],1)
        self.assertEqual(report["evaluation"]["fp"],0)
    def test_duplicate_id_rejected(self):
        e={"id":"1","host":"s","timestamp":"2026-10-22T10:00:00Z","kind":"http_anomaly"}
        with self.assertRaises(ValueError):
            run([e,e])
    def test_unlabeled_host_rejected(self):
        e={"id":"1","host":"s","timestamp":"2026-10-22T10:00:00Z","kind":"http_anomaly"}
        with self.assertRaises(ValueError):
            run([e],[{"id":"other","label":"benign"}])
