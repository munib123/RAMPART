# Vulnerability: iBarn Installer - Exposure
**Classification:** IBARN
**Source:** Nuclei Template (`ibarn-installer.yaml`)

## Description
Detects the exposure of the iBarn installer page, which could allow unauthorized setup or reinstallation of the application.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

