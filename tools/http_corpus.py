#!/usr/bin/env python3
"""Generate harmless deterministic HTTP request fixtures and their labels.

No exploit payload, network access or PHP endpoint is involved.
"""
import argparse
import json
from pathlib import Path

CASES = [
    ("small_php_post", "/index.php", 128, False),
    ("large_php_upload", "/upload.php", 450000, True),
    ("large_api_post", "/api/data", 450000, False),
    ("small_php_form", "/submit.php", 4096, False),
    ("large_php_report", "/report.php", 800000, True),
]

def make_corpus(output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    manifest = []
    for name, path, size, expected in CASES:
        # The fixture intentionally includes no PHP2Shell attack material.
        request = (
            f"POST {path} HTTP/1.1\r\nHost: example.invalid\r\n"
            f"Content-Type: application/octet-stream\r\n"
            f"Content-Length: {size}\r\n\r\n"
        )
        filename = name + ".http"
        (output / filename).write_bytes(request.encode("ascii"))
        manifest.append({"name": name, "file": filename,
                         "expected_large_php_post_heuristic": expected,
                         "note": "synthetic header-only fixture; no request body"})
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--output", default="tests/generated-http")
    args = p.parse_args()
    print(json.dumps(make_corpus(args.output), indent=2))
