# Vulnerability: ExtraLunchMoney User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`extralunchmoney.yaml`)

## Description
ExtraLunchMoney user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://extralunchmoney.com/user/{{user}}
```

