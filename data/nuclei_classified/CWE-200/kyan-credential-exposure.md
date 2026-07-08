# Vulnerability: Kyan Credential - Exposure
**Classification:** CWE-200
**Source:** Nuclei Template (`kyan-credential-exposure.yaml`)

## Description
Kyan Network login panel was detected. Password and other credential theft is possible via accessing this panel.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/hosts
```

