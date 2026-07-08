# Vulnerability: Pichome Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`pichome-panel.yaml`)

## Description
Pichome login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/user.php?mod=login
```

