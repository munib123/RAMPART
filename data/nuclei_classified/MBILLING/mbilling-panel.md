# Vulnerability: MagnusBilling - Login Panel
**Classification:** MBILLING
**Source:** Nuclei Template (`mbilling-panel.yaml`)

## Description
Identified an exposed MagnusBilling login panel.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/mbilling/
```

