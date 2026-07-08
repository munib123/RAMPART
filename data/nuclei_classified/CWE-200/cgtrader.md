# Vulnerability: CGTrader User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`cgtrader.yaml`)

## Description
CGTrader user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.cgtrader.com/{{user}}
```

