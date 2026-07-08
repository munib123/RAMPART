# Vulnerability: Risk.ru User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`riskru.yaml`)

## Description
Risk.ru user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://risk.ru/people/{{user}}
```

