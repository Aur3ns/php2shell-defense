import tempfile
import unittest
from pathlib import Path
from tools.http_corpus import make_corpus

class CorpusTests(unittest.TestCase):
    def test_deterministic_and_labeled(self):
        with tempfile.TemporaryDirectory() as tmp:
            rows = make_corpus(tmp)
            self.assertEqual(len(rows), 5)
            self.assertEqual(sum(x["expected_large_php_post_heuristic"] for x in rows), 2)
            a = {p.name: p.read_bytes() for p in Path(tmp).glob("*.http")}
            make_corpus(tmp)
            b = {p.name: p.read_bytes() for p in Path(tmp).glob("*.http")}
            self.assertEqual(a, b)

    def test_no_exploitation(self):
        with tempfile.TemporaryDirectory() as tmp:
            make_corpus(tmp)
            text = b"".join(p.read_bytes() for p in Path(tmp).glob("*.http"))
            self.assertNotIn(b"PHP_SESSION_UPLOAD_PROGRESS", text)
            self.assertNotIn(b"JACKALPOC", text)
