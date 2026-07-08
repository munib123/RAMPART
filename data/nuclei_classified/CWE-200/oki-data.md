# Vulnerability: OKI Data Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`oki-data.yaml`)

## Description
OKI Data panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/status.htm
```

