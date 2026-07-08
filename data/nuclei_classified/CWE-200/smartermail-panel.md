# Vulnerability: SmarterMail Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`smartermail-panel.yaml`)

## Description
SmarterMail login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Login.aspx
```

