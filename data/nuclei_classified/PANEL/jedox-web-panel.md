# Vulnerability: Jedox Web Login Panel - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`jedox-web-panel.yaml`)

## Description
Jedox is an Enterprise Performance Management software which is used for planning, analytics and reporting  in finance and other areas such as sales, human resources and procurement.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/ui/login/
```

