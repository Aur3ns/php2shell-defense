import unittest
from tools.evaluate import evaluate

class EvaluationTests(unittest.TestCase):
    def test_counts(self):
        a=[{"id":"b1","label":"benign"},{"id":"b2","label":"benign"},
           {"id":"s1","label":"suspicious"},{"id":"s2","label":"suspicious"}]
        result=evaluate(a,[{"id":"b1"},{"id":"s1"}])
        self.assertEqual((result["tp"],result["fp"],result["tn"],result["fn"]),(1,1,1,1))
        self.assertEqual(result["precision"],0.5)
        self.assertEqual(result["false_positive_rate"],0.5)

    def test_no_positives_are_null(self):
        result=evaluate([{"id":"b","label":"benign"}],[])
        self.assertIsNone(result["precision"])
        self.assertIsNone(result["recall"])

    def test_no_silent_unknown_cases(self):
        with self.assertRaises(ValueError):
            evaluate([{"id":"known","label":"benign"}],[{"id":"unknown"}])

    def test_reject_duplicate(self):
        with self.assertRaises(ValueError):
            evaluate([{"id":"x","label":"benign"},{"id":"x","label":"benign"}],[])

    def test_reject_duplicate_alert(self):
        with self.assertRaises(ValueError):
            evaluate([{"id":"x","label":"benign"}],[{"id":"x"},{"id":"x"}])
