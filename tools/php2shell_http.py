"""Bounded, defensive triage of already-captured HTTP metadata.

Presence of a PHP upload-progress field can be legitimate. Never infer compromise.
"""
import re
from collections import Counter

def inspect_request(method, path, content_type, body, max_bytes=2_000_000):
    if not isinstance(body, bytes): raise TypeError("body must be bytes")
    if len(body)>max_bytes: return {"confidence":"unknown","reason":"body_limit_exceeded"}
    if method.upper()!="POST" or not path.lower().split("?")[0].endswith(".php"):
        return {"confidence":"none","reason":"outside_scope"}
    if "multipart/form-data" not in content_type.lower():
        return {"confidence":"none","reason":"not_multipart"}
    fields=re.findall(rb'(?im)Content-Disposition:[^\r\n]{0,4096}\bname="([^"\r\n]{1,512})"',body)
    counts=Counter(fields)
    progress=any(key == b"PHP_SESSION_UPLOAD_PROGRESS" for key in counts)
    repeated=sum(n for key,n in counts.items() if key.endswith(b"[]") and n>1)
    if progress and repeated>=100:
        return {"confidence":"elevated","reason":"upload_progress_plus_repeated_array_fields",
                "array_parts":repeated}
    if progress:
        return {"confidence":"context","reason":"upload_progress_field_observed"}
    return {"confidence":"none","reason":"no_selected_indicators"}

