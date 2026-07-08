# Vulnerability: Ogu.gg User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ogugg.yaml`)

## Description
Ogu.gg user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://ogu.gg/{{user}}
```

