# Vulnerability: OPGG User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`opgg.yaml`)

## Description
OPGG user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://eune.op.gg/summoners/eune/{{user}}
```

