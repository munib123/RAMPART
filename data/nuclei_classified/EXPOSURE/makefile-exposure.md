# Vulnerability: Makefile - Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`makefile-exposure.yaml`)

## Description
Detected Makefile configuration file was identified, which potentially exposed build process details, author information, and directory structure

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Makefile
GET {{BaseURL}}/makefile
```

