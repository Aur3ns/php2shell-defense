"""Offline normalization of selected Suricata EVE, Falco and Wazuh alerts.

Only well-defined detection IDs are mapped. Generic vendor alerts are not
automatically asserted to be PHP2Shell indicators.
"""
from datetime import datetime, timezone

def stamp(value):
    if not isinstance(value,str): raise ValueError("timestamp missing")
    from datetime import datetime
    value=value.replace("Z","+00:00")
    dt=datetime.fromisoformat(value)
    if dt.tzinfo is None: raise ValueError("timestamp timezone required")
    return dt.astimezone(timezone.utc).isoformat()

def normalize(source, row, *, identity=None):
    if not isinstance(row,dict): raise ValueError("event must be object")
    identity = identity or {}
    if source == "suricata":
        if row.get("event_type") != "alert" or row.get("alert",{}).get("signature_id") != 9900101:
            return None
        host=identity.get("suricata_destination_host") or row.get("dest_ip")
        kind="http_anomaly"
        timestamp=row.get("timestamp")
    elif source == "falco":
        if row.get("rule") != "Unexpected shell or downloader spawned by PHP worker":
            return None
        host=row.get("hostname") or row.get("host")
        kind="web_child_process"
        timestamp=row.get("time")
    elif source == "wazuh":
        rule=str(row.get("rule",{}).get("id",""))
        if rule not in {"100510","100511"}: return None
        host=row.get("agent",{}).get("name")
        kind="web_child_process" if rule=="100510" else "php_memory_error"
        timestamp=row.get("timestamp")
    else:
        raise ValueError("unsupported source")
    if not isinstance(host,str) or not host or len(host)>255:
        raise ValueError("missing host identity; configure an identity mapping")
    return {"host":host,"timestamp":stamp(timestamp),"kind":kind}

def normalize_many(source, records, identity=None):
    result=[]
    for i, row in enumerate(records):
        event=normalize(source,row,identity=identity)
        if event is not None:
            event["id"]=f"{source}-{i}"
            result.append(event)
    return result
