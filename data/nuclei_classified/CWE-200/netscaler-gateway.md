# Vulnerability: Netscaler Gateway
**Classification:** CWE-200
**Source:** Nuclei Template (`netscaler-gateway.yaml`)

## Description
Citrix NetScaler is an application delivery controller that improves the delivery speed and quality of applications to an end user.

## Secure Mitigation
Ensure proper access.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/vpn/index.html
```

