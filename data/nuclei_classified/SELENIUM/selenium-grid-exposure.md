# Vulnerability: Selenium Grid Exposure
**Classification:** SELENIUM
**Source:** Nuclei Template (`selenium-grid-exposure.yaml`)

## Description
Detected Selenium Grid console without authentication, exposing internal network IPs, container names, OS details, software versions, and browser node configurations. Attackers could abuse this for SSRF, internal reconnaissance, or resource hijacking.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wd/hub/status
```

