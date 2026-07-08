# Vulnerability: Oracle E-Business System Credentials Page - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`oracle-ebs-credentials.yaml`)

## Description
Oracle E-Business System credentials page was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/OA_HTML/jtfwrepo.xml
```

