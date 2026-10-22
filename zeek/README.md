# Experimental Zeek HTTP metadata detector

Load `__load__.zeek` in a Zeek deployment that already parses HTTP.
It emits the `PHP2SHELLDefense::Large_PHP_POST` notice for an HTTP POST
to a `.php` endpoint with declared Content-Length >= 300000 bytes.

**This is NOT a PHP2Shell-specific detection.** Large PHP uploads are often
legitimate, and request headers can be spoofed. The detector does not inspect
multipart fields, exploit payloads, PHP session state, or runtime behavior.
It cannot identify chunked requests with no Content-Length. Only deploy in
alert-only mode; tune `min_request_bytes` for the local environment.

Native CI syntax validation does **not** verify expected notices against
packet fixtures. Synthetic Zeek behavioral test coverage is a separate release
requirement that is not yet met.
