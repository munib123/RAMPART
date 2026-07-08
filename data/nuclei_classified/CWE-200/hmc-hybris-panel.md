# Vulnerability: Hybris Management Console Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`hmc-hybris-panel.yaml`)

## Description
Hybris Management Console login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/hmc/hybris
GET {{BaseURL}}/hybris/hmc/hybris
```

