# Vulnerability: Sophos Firewall Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`sophos-fw-version-detect.yaml`)

## Description
Sophos Firewall login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/webconsole/webpages/login.jsp
GET {{BaseURL}}/userportal/webpages/myaccount/login.jsp
```

