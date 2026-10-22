import unittest
from tools.php2shell_http import inspect_request

def multipart(parts):
    return b"\r\n".join(b'Content-Disposition: form-data; name="'+x+b'"' for x in parts)

class MechanicsTests(unittest.TestCase):
    def call(self,parts,path="/upload.php"):
        return inspect_request("POST",path,"multipart/form-data; boundary=example",multipart(parts))
    def test_progress_field_alone_is_context(self):
        self.assertEqual(self.call([b"PHP_SESSION_UPLOAD_PROGRESS"])["confidence"],"context")
    def test_combined_indicators_elevated(self):
        case=[b"PHP_SESSION_UPLOAD_PROGRESS"]+[b"example[]"]*101
        self.assertEqual(self.call(case)["confidence"],"elevated")
    def test_array_repetition_without_progress_is_none(self):
        self.assertEqual(self.call([b"example[]"]*150)["confidence"],"none")
    def test_non_php_route_ignored(self):
        self.assertEqual(self.call([b"PHP_SESSION_UPLOAD_PROGRESS"],path="/upload")["confidence"],"none")
    def test_max_bytes(self):
        result=inspect_request("POST","/upload.php","multipart/form-data",b"x"*100,10)
        self.assertEqual(result["confidence"],"unknown")
    def test_benign_upload(self):
        self.assertEqual(self.call([b"file",b"description"])["confidence"],"none")
