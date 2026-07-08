# Vulnerability: MyLot User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mylot.yaml`)

## Description
MyLot user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.mylot.com/{{user}}
```

