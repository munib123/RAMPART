# Vulnerability: Hybris Administration Console Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`hybris-administration-console.yaml`)

## Description
Hybris Administration Console login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

