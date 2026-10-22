# Telemetry prerequisites

* Linux process-creation audit or EDR events with process parent and executable.
* PHP-FPM, Apache/Nginx error logs with stable hostname/timestamp.
* Proxy/WAF request sizes, status, method and normalized paths; redact secrets.
* A common time source for multi-signal correlation.
* Wazuh UID fields differ by system: do not assume 33/48/99 applies everywhere.