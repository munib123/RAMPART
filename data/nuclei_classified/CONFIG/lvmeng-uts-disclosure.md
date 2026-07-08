# Vulnerability: Lvmeng - UTS Disclosure
**Classification:** CONFIG
**Source:** Nuclei Template (`lvmeng-uts-disclosure.yaml`)

## Description
Lvmeng UTS was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/webapi/v1/system/accountmanage/account
```

