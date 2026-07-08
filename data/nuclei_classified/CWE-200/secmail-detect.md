# Vulnerability: SecMail Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`secmail-detect.yaml`)

## Description
SecMail login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/SecMail/login.jsp
```

