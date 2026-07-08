# Vulnerability: WHM Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`whm-login-detect.yaml`)

## Description
WHM login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
```

