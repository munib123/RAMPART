# Vulnerability: Gitlab Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`gitlab-detect.yaml`)

## Description
Gitlab login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/users/sign_in
```

