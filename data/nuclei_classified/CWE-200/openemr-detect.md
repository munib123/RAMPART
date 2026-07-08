# Vulnerability: OpenEMR Product Registration Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`openemr-detect.yaml`)

## Description
OpenEMR Product Registration panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/interface/login/login.php?site=default
```

