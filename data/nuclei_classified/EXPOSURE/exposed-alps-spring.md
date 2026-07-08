# Vulnerability: Exposed Spring Data REST Application-Level Profile Semantics (ALPS)
**Classification:** EXPOSURE
**Source:** Nuclei Template (`exposed-alps-spring.yaml`)

## Description
Exposed Spring Data profile semantics is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/profile
GET {{BaseURL}}/api/profile
GET {{BaseURL}}/alps/profile
```

