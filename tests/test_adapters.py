import unittest
from tools.adapters import normalize, normalize_many

class AdaptersTest(unittest.TestCase):
    def test_suricata(self):
        row={"event_type":"alert","timestamp":"2026-10-22T10:00:00+00:00",
             "dest_ip":"192.0.2.1","alert":{"signature_id":9900101}}
        self.assertEqual(normalize("suricata",row)["kind"],"http_anomaly")
        self.assertEqual(normalize("suricata",row,identity={"suricata_destination_host":"web"})["host"],"web")
    def test_unknown_signature_ignored(self):
        self.assertIsNone(normalize("suricata",{"event_type":"alert","alert":{"signature_id":12}}))
    def test_falco(self):
        r={"rule":"Unexpected shell or downloader spawned by PHP worker",
           "time":"2026-10-22T10:00:01Z","hostname":"web"}
        self.assertEqual(normalize("falco",r)["kind"],"web_child_process")
    def test_wazuh(self):
        r={"rule":{"id":"100511"},"agent":{"name":"web"},"timestamp":"2026-10-22T10:00:01Z"}
        self.assertEqual(normalize("wazuh",r)["kind"],"php_memory_error")
    def test_bad_time_rejected(self):
        r={"rule":{"id":"100511"},"agent":{"name":"web"},"timestamp":"2026-10-22T10:00:01"}
        with self.assertRaises(ValueError): normalize("wazuh",r)
    def test_invalid_host_rejected(self):
        r={"rule":{"id":"100511"},"timestamp":"2026-10-22T10:00:01Z"}
        with self.assertRaises(ValueError): normalize("wazuh",r)
    def test_ids_stable(self):
        r={"rule":{"id":"100511"},"agent":{"name":"web"},"timestamp":"2026-10-22T10:00:01Z"}
        self.assertEqual(normalize_many("wazuh",[r,r])[1]["id"],"wazuh-1")
