# Vulnerability: HP iLO Serial Key - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`hp-ilo-serial-key-disclosure.yaml`)

## Description
HP iLO serial key was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/xmldata?item=CpqKey
```

