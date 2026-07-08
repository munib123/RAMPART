# Vulnerability: Browser Configuration "browserconfig.xml" Exposure
**Classification:** BROWSERCONFIG
**Source:** Nuclei Template (`browserconfig-xml.yaml`)

## Description
Browser Configuration "browserconfig.xml" File was exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/browserconfig.xml
```

