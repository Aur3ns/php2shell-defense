# Conservative PHP2Shell HTTP triage

`tools/php2shell_http.py` analyzes **pre-captured body bytes only**. It does not send probes or replay exploits.

A multipart POST to a PHP endpoint containing a `PHP_SESSION_UPLOAD_PROGRESS` field combined with many repeated array-form fields receives the `elevated` heuristic classification. The field alone is labeled `context`. This signal is **not unique to PHP2Shell**, not evidence of RCE, and does not cover both CVEs or every variant.

Only bounded captured bodies are inspected. Exceeding the size budget yields `unknown`, not `clean`. No body contents are returned. Never enable blocking solely from this experimental analysis.

This is an independently implemented research heuristic. Compare and evaluate against benign multipart upload cases; do not copy third-party rules without license review. Native Wazuh and Zeek workflows are separate **experimental** checks, not proof of detection efficacy.
