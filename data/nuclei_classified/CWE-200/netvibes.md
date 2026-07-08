# Vulnerability: Netvibes User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`netvibes.yaml`)

## Description
Netvibes user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.netvibes.com/{{user}}
```

