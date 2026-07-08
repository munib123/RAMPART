# Vulnerability: Rsi User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`rsi.yaml`)

## Description
Rsi user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://robertsspaceindustries.com/citizens/{{user}}
```

