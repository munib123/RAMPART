# Vulnerability: WordPress Wordfence - WAF Logs and Data Disclosure
**Classification:** CWE-538
**Source:** Nuclei Template (`wordfence-waf-logs-disclosure.yaml`)

## Description
The Wordfence Security plugin creates various log and data files in the wflogs directory. If directory listing is enabled or files are directly accessible, sensitive information about blocked attacks, IP addresses, and firewall configuration may be exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/wp-content/wflogs/
GET {{BaseURL}}/wp-content/plugins/wordfence/lib/wflogs/
GET {{BaseURL}}/wp-content/plugins/wordfence/tmp/
```

