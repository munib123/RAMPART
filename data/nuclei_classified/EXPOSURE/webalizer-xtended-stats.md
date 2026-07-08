# Vulnerability: Webalizer Xtended Statistics Exposed
**Classification:** EXPOSURE
**Source:** Nuclei Template (`webalizer-xtended-stats.yaml`)

## Description
Webalizer Xtended Statistics is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/usage/
```

