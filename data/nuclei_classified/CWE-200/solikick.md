# Vulnerability: SoliKick User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`solikick.yaml`)

## Description
SoliKick user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://solikick.com/-{{user}}
```

