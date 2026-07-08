# Vulnerability: Ebay stores User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ebay-stores.yaml`)

## Description
Ebay stores user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.ebay.com/str/{{user}}
```

