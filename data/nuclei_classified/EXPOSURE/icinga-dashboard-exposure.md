# Vulnerability: Icinga Exposed Dashboard
**Classification:** EXPOSURE
**Source:** Nuclei Template (`icinga-dashboard-exposure.yaml`)

## Description
Icinga Dashboard was exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/icinga2
```

