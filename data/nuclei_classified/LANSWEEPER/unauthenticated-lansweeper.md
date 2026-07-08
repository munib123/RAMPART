# Vulnerability: Unauthenticated Lansweeper Instance
**Classification:** LANSWEEPER
**Source:** Nuclei Template (`unauthenticated-lansweeper.yaml`)

## Description
Lansweeper Instance is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Default.aspx
```

