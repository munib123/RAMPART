# Vulnerability: PQube 3 Power Analyzers
**Classification:** IOT
**Source:** Nuclei Template (`pqube-power-analyzers.yaml`)

## Description
PQube 3 Power Analyzer panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/status.html
```

