# Vulnerability: MistServer Installation Wizard - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`mistserver-installer.yaml`)

## Description
MistServer installation/setup wizard is publicly accessible, allowing unauthorized users to create admin accounts and take full control of the streaming server. This is a first-user-wins vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

