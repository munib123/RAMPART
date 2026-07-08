# Vulnerability: Paypal User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`paypal.yaml`)

## Description
Paypal user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.paypal.com/paypalme/{{user}}
```

