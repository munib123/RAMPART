# Vulnerability: Ivanti Xtraction - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ivanti-xtraction-detect.yaml`)

## Description
Detects Ivanti Xtraction, a reporting and dashboard platform used with Ivanti products.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/xtraction
```

