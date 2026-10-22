import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class DetectionCatalogTests(unittest.TestCase):
    def test_catalog_schema_and_fields(self):
        data = json.loads((ROOT / "catalog/detections.json").read_text())
        self.assertEqual(data["schema_version"], 1)
        self.assertGreaterEqual(len(data["detections"]), 5)
        ids = set()
        for d in data["detections"]:
            self.assertNotIn(d["id"], ids)
            ids.add(d["id"])
            self.assertIn(d["confidence"], ("low", "medium", "high"))
            self.assertIsInstance(d["native_tested"], bool)
            self.assertTrue(d["platforms"])
            self.assertTrue(d["telemetry"])
            self.assertTrue(d["false_positives"])


if __name__ == "__main__":
    unittest.main()
