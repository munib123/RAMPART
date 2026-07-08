# Vulnerability: IBM API Connect Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`ibm-api-connect-panel.yaml`)

## Description
IBM API Connect login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/auth/manager/sign-in/
GET {{BaseURL}}
```

