# Vulnerability: Citrix ADC Gateway Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`citrix-adc-gateway-panel.yaml`)

## Description
Citrix ADC Gateway login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/logon/LogonPoint/index.html
GET {{BaseURL}}/logon/LogonPoint/custom.html
```

