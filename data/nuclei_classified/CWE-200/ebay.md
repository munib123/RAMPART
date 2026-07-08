# Vulnerability: EBay User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ebay.yaml`)

## Description
EBay user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.ebay.com/usr/{{user}}
```

