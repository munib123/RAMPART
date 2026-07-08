# Vulnerability: Epson Device Unauthorized Access Detect
**Classification:** CWE-668
**Source:** Nuclei Template (`epson-access-detect.yaml`)

## Description
A publicly available Epson device panel (printer, scanner, etc.) was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/PRESENTATION/EPSONCONNECT
```

