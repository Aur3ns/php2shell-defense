"""Bounded triage of captured multipart HTTP requests. Never proves exploitation."""
from collections import Counter
from email.message import Message

def inspect_request(method, path, content_type, body, max_bytes=2_000_000):
    if not isinstance(body, bytes):
        raise TypeError("body must be bytes")
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 0:
        raise ValueError("invalid byte budget")
    if len(body) > max_bytes:
        return {"confidence":"unknown","reason":"body_limit_exceeded"}
    if method.upper() != "POST" or not path.lower().split("?",1)[0].endswith(".php"):
        return {"confidence":"none","reason":"outside_scope"}
    msg=Message()
    msg["Content-Type"]=content_type
    if msg.get_content_type() != "multipart/form-data":
        return {"confidence":"none","reason":"not_multipart"}
    boundary=msg.get_param("boundary",header="content-type")
    if not boundary or not isinstance(boundary,str) or len(boundary)>70:
        return {"confidence":"unknown","reason":"invalid_boundary"}
    try:
        marker=b"--"+boundary.encode("ascii")
    except UnicodeEncodeError:
        return {"confidence":"unknown","reason":"invalid_boundary"}
    # A marker must start at the beginning of the body or after CRLF.
    segments=body.split(marker)
    if len(segments)<3 or segments[0] not in (b"",b"\r\n"):
        return {"confidence":"unknown","reason":"incomplete_multipart"}
    if segments[-1] not in (b"--", b"--\r\n"):
        return {"confidence":"unknown","reason":"invalid_closing_boundary"}
    if len(segments) > 10002:
        return {"confidence":"unknown","reason":"part_limit_exceeded"}
    fields=Counter()
    for segment in segments[1:-1]:
        if not segment.startswith(b"\r\n") or not segment.endswith(b"\r\n"):
            return {"confidence":"unknown","reason":"malformed_part"}
        header_end=segment.find(b"\r\n\r\n")
        if header_end<0 or header_end>8192:
            return {"confidence":"unknown","reason":"malformed_part"}
        headers=segment[2:header_end].split(b"\r\n")
        if any(not line or b":" not in line for line in headers):
            return {"confidence":"unknown","reason":"malformed_headers"}
        for line in headers:
            if line.lower().startswith(b"content-disposition:"):
                disposition=line.split(b":",1)[1].strip()
                if not disposition.lower().startswith(b"form-data;"):
                    continue
                for item in disposition.split(b";")[1:]:
                    item=item.strip()
                    if item.lower().startswith(b"name=") and len(item)>5:
                        val=item[5:].strip().strip(b'"')
                        if 0<len(val)<=512:
                            fields[val]+=1
                        break
    progress=b"PHP_SESSION_UPLOAD_PROGRESS" in fields
    repeated=sum(n for field,n in fields.items() if field.endswith(b"[]") and n>1)
    if progress and repeated>=100:
        return {"confidence":"elevated","reason":"upload_progress_plus_repeated_array_fields","array_parts":repeated}
    if progress:
        return {"confidence":"context","reason":"upload_progress_field_observed"}
    return {"confidence":"none","reason":"no_selected_indicators"}
