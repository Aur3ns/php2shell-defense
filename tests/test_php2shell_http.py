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
    def test_near_threshold_not_elevated(self):
        fields=[b"PHP_SESSION_UPLOAD_PROGRESS"]+[b"items[]"]*99
        self.assertEqual(self.call(fields)["confidence"],"context")
    def test_query_suffix(self):
        fields=[b"PHP_SESSION_UPLOAD_PROGRESS"]+[b"items[]"]*100
        self.assertEqual(self.call(fields,path="/index.php?view=1")["confidence"],"elevated")
    def test_benign_repeated_array(self):
        self.assertEqual(self.call([b"tags[]"]*120)["confidence"],"none")
    def test_wrong_http_method(self):
        body=multipart([b"PHP_SESSION_UPLOAD_PROGRESS"]+[b"items[]"]*110)
        self.assertEqual(inspect_request("GET","/index.php","multipart/form-data",body)["confidence"],"none")
    def test_wrong_content_type(self):
        body=multipart([b"PHP_SESSION_UPLOAD_PROGRESS"]+[b"items[]"]*110)
        self.assertEqual(inspect_request("POST","/index.php","application/json",body)["confidence"],"none")
    def test_benign_upload(self):
        self.assertEqual(self.call([b"file",b"description"])["confidence"],"none")
