# Vulnerability: Oracle Reports Services - Servlet
**Classification:** EXPOSURE
**Source:** Nuclei Template (`oracle-reports-services.yaml`)

## Description
Oracle Reports Services - Servlet Command dashboard

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/reports/
GET {{BaseURL}}/ora/reports/
GET {{BaseURL}}/oracle/reports/
```

