# Vulnerability: Buymeacoffee User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`buymeacoffee.yaml`)

## Description
Buymeacoffee user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.buymeacoffee.com/{{user}}
```

