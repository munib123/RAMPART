# Vulnerability: Splunk SOAR Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`splunk-login.yaml`)

## Description
Splunk SOAR login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login?next=/
```

