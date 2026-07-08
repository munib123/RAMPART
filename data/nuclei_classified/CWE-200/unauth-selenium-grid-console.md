# Vulnerability: Selenium Grid Console - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`unauth-selenium-grid-console.yaml`)

## Description
Selenium Grid Console panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/grid/console
GET {{BaseURL}}/console
```

