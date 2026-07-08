# Vulnerability: Akamai CloudTest Panel
**Classification:** CWE-200
**Source:** Nuclei Template (`akamai-cloudtest.yaml`)

## Description
An Akamai CloudTest panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/concerto/Login?goto=Central
```

