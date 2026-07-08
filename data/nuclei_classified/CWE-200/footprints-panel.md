# Vulnerability: FootPrints Service Core Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`footprints-panel.yaml`)

## Description
FootPrints Service Core login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/MRcgi/MRlogin.pl
GET {{BaseURL}}/MRcgi/MRentrancePage.pl
```

