# Vulnerability: Acrolinx Dashboard
**Classification:** CWE-200
**Source:** Nuclei Template (`acrolinx-dashboard.yaml`)

## Description
An Acrolinx Analytics dashboard was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/dashboard.html
```

