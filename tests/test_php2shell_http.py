import unittest
from tools.php2shell_http import inspect_request

def multipart(fields):
    chunks=[]
    for name in fields:
        chunks.append(b"--example\r\nContent-Disposition: form-data; name=\"" + name + b"\"\r\n\r\nvalue\r\n")
    return b"".join(chunks)+b"--example--\r\n"

class MechanicsTests(unittest.TestCase):
    def call(self, fields, path="/upload.php"):
        return inspect_request("POST",path,"multipart/form-data; boundary=example",multipart(fields))
    def test_progress_alone_context(self):
        self.assertEqual(self.call([b"PHP_SESSION_UPLOAD_PROGRESS"])["confidence"],"context")
    def test_combined_elevated(self):
        self.assertEqual(self.call([b"PHP_SESSION_UPLOAD_PROGRESS"]+[b"tags[]"]*101)["confidence"],"elevated")
    def test_benign_repeated_array(self):
        self.assertEqual(self.call([b"tags[]"]*120)["confidence"],"none")
    def test_threshold(self):
        self.assertEqual(self.call([b"PHP_SESSION_UPLOAD_PROGRESS"]+[b"tags[]"]*99)["confidence"],"context")
    def test_non_php(self):
        self.assertEqual(self.call([b"PHP_SESSION_UPLOAD_PROGRESS"],"/upload")["confidence"],"none")
    def test_query(self):
        self.assertEqual(self.call([b"PHP_SESSION_UPLOAD_PROGRESS"],"/index.php?x=1")["confidence"],"context")
    def test_budget(self):
        self.assertEqual(inspect_request("POST","/a.php","multipart/form-data; boundary=example",b"x"*20,10)["confidence"],"unknown")
    def test_bad_boundary(self):
        self.assertEqual(inspect_request("POST","/a.php","multipart/form-data",b"")["reason"],"invalid_boundary")
    def test_no_closing_marker(self):
        self.assertEqual(inspect_request("POST","/a.php","multipart/form-data; boundary=example",b"--example\r\ncontent")["reason"],"incomplete_multipart")
    def test_header_like_payload_not_fields(self):
        body=(b"--example\r\nContent-Disposition: form-data; name=\"safe\"\r\n\r\n"
              +b"Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n"
              +b"Content-Disposition: form-data; name=\"tags[]\"\r\n"*110
              +b"\r\n--example--\r\n")
        self.assertEqual(inspect_request("POST","/a.php","multipart/form-data; boundary=example",body)["confidence"],"none")
    def test_wrong_method(self):
        self.assertEqual(inspect_request("GET","/a.php","multipart/form-data; boundary=example",multipart([b"PHP_SESSION_UPLOAD_PROGRESS"]))["confidence"],"none")
    def test_wrong_type(self):
        self.assertEqual(inspect_request("POST","/a.php","application/json",multipart([b"PHP_SESSION_UPLOAD_PROGRESS"]))["confidence"],"none")

    def test_invalid_closing_boundary_rejected(self):
        body=multipart([b"PHP_SESSION_UPLOAD_PROGRESS"])+b"garbage"
        self.assertEqual(
            inspect_request("POST","/a.php","multipart/form-data; boundary=example",body)["confidence"],
            "unknown")
    def test_embedded_boundary_is_not_accepted_as_valid_multipart(self):
        body=(b"--example\\r\\nContent-Disposition: form-data; name=\\\"safe\\\""
              b"\\r\\n\\r\\ntext--examplefake\\r\\n--example--\\r\\n")
        self.assertEqual(
            inspect_request("POST","/a.php","multipart/form-data; boundary=example",body)["confidence"],
            "none")
    def test_invalid_resource_budget_rejected(self):
        with self.assertRaises(ValueError):
            inspect_request("POST","/a.php","multipart/form-data; boundary=example",b"", -1)
