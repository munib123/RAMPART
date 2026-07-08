# Vulnerability: CaringBridge User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`caringbridge.yaml`)

## Description
CaringBridge user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.caringbridge.org/visit/{{user}}
```

