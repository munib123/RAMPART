# Vulnerability: HP Virtual Connect Manager Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`hp-virtual-connect-manager.yaml`)

## Description
HP Virtual Connect Manager login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/html/index.html
```

