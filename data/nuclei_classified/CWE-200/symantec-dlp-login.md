# Vulnerability: Symantec Data Loss Prevention Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`symantec-dlp-login.yaml`)

## Description
Symantec Data Loss Prevention login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ProtectManager/Logon
```

