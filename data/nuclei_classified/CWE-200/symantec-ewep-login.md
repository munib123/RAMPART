# Vulnerability: Symantec Encryption Server Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`symantec-ewep-login.yaml`)

## Description
Symantec Encryption Server login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/b/l.e
```

