# Vulnerability: ProfitTrailer Setup Page - Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`profittrailer-installer.yaml`)

## Description
Detects exposed ProfitTrailer Setup page.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/setup/license
```

