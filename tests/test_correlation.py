import unittest
from tools.correlate import correlate

def event(host, t, kind):
    return {"host":host, "timestamp":t, "kind":kind}

class TestCorrelation(unittest.TestCase):
    def test_detects_nearby_independent_signals(self):
        rows=[event("web-1","2026-10-22T10:00:00Z","http_anomaly"),
              event("web-1","2026-10-22T10:00:30Z","web_child_process")]
        result=correlate(rows)
        self.assertEqual(len(result),1)
        self.assertEqual(result[0]["score"],3)
    def test_only_post_not_alert(self):
        self.assertEqual(correlate([event("web-1","2026-10-22T10:00:00Z","http_anomaly")]),[])
    def test_cross_host_not_correlated(self):
        rows=[event("web-1","2026-10-22T10:00:00Z","http_anomaly"),
              event("web-2","2026-10-22T10:00:01Z","web_child_process")]
        self.assertEqual(correlate(rows),[])
    def test_far_apart_not_alert(self):
        rows=[event("web-1","2026-10-22T10:00:00Z","http_anomaly"),
              event("web-1","2026-10-22T10:20:00Z","web_child_process")]
        self.assertEqual(correlate(rows),[])
    def test_reject_naive_timestamp(self):
        with self.assertRaises(ValueError):
            correlate([event("web-1","2026-10-22T10:00:00","http_anomaly")])
    def test_reject_unknown_kind(self):
        with self.assertRaises(ValueError):
            correlate([event("web-1","2026-10-22T10:00:00Z","made_up")])

if __name__ == "__main__":
    unittest.main()
