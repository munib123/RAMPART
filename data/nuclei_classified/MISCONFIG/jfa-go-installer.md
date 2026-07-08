# Vulnerability: jfa-go Setup Page - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`jfa-go-installer.yaml`)

## Description
Detects exposed jfa-go Setup page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

