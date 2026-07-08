# Vulnerability: Lotus Domino Configuration Page
**Classification:** EXPOSURE
**Source:** Nuclei Template (`domcfg-page.yaml`)

## Description
Lotus Domino configuration file is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/domcfg.nsf
```

