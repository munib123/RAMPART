# Vulnerability: Cal User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`cal.yaml`)

## Description
Cal user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://cal.com/{{user}}
```

