# Vulnerability: Pokec User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`pokec.yaml`)

## Description
Pokec user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://pokec.azet.sk/{{user}}
```

