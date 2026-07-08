# Vulnerability: HAL Management Console Panel
**Classification:** PANEL
**Source:** Nuclei Template (`hal-management-panel.yaml`)

## Description
HAL Management Console login panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/console/index.html
```

