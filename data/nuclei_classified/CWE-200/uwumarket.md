# Vulnerability: Uwumarket User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`uwumarket.yaml`)

## Description
Uwumarket user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://uwumarket.us/collections/{{user}}
```

