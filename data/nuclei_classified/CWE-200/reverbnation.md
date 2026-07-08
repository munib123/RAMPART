# Vulnerability: ReverbNation User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`reverbnation.yaml`)

## Description
ReverbNation user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.reverbnation.com/{{user}}
```

