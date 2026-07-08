# Vulnerability: WeTransfer User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`wetransfer.yaml`)

## Description
WeTransfer user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://{{user}}.wetransfer.com
```

