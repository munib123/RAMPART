# Vulnerability: Teddygirls User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`teddygirls.yaml`)

## Description
Teddygirls user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://teddysgirls.net/models/{{user}}
```

