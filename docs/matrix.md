# Detection confidence

| Platform | Signal | Specificity |
|---|---|---|
| Sigma / Elastic / Falco | Web child shell/tool | Medium, generic |
| Wazuh | Web UID process, PHP OOM | Low-medium |
| Splunk | Web child process / PHP OOM | Medium / low |
| Suricata / ModSecurity | Large POST to PHP route | Low |
| Loki | PHP memory errors | Low |

An in-process exploit may produce no child process. None of these observations, alone, prove PHP2Shell exploitation.