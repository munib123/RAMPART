# Vulnerability: Eagle For Apache Kakfa Login - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`efak-login-panel.yaml`)

## Description
EFAK is a visualization and management software that allows one to query, visualize, alert on, and explore their metrics wherever they were stored.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/account/signin?/
```

