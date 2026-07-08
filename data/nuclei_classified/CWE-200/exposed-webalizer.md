# Vulnerability: Webalizer Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`exposed-webalizer.yaml`)

## Description
Webalizer panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/webalizer/
```

