# Vulnerability: Kaeser Sigma Air Manager - Panel
**Classification:** KAESER
**Source:** Nuclei Template (`kaeser-sigma-air-manager-panel.yaml`)

## Description
Detected exposed Kaeser Sigma Air Manager login panel

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/HMI/login.html
```

