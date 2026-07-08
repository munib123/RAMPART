# Vulnerability: NETSurveillance Web Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`netsurveillance-web.yaml`)

## Description
NETSurveillance Web panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Login.htm
```

