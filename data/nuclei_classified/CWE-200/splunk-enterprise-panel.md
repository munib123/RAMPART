# Vulnerability: Splunk Enterprise Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`splunk-enterprise-panel.yaml`)

## Description
Splunk Enterprise login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/en-US/account/login
```

