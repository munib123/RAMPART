# Vulnerability: TYPO3 Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`typo3-login.yaml`)

## Description
TYPO3 login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/typo3/
```

