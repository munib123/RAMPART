# Vulnerability: Covenant C2 - Detect
**Classification:** C2
**Source:** Nuclei Template (`covenant-c2.yaml`)

## Description
Covenant is a .NET command and control framework that aims to highlight the attack surface of .NET, make the use of offensive .NET tradecraft easier,and serve as a collaborative command and control platform for red teamers.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/covenantuser/login
```

