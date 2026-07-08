# Vulnerability: Tradingview User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`tradingview.yaml`)

## Description
Tradingview user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.tradingview.com/u/{{user}}/
```

