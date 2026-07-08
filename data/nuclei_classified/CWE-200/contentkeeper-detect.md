# Vulnerability: ContentKeeper Cloud Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`contentkeeper-detect.yaml`)

## Description
ContentKeeper Cloud panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cgi-bin/ck/domenu.cgi
```

