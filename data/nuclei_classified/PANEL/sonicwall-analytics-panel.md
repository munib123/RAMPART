# Vulnerability: SonicWall Analytics - Login Panel
**Classification:** PANEL
**Source:** Nuclei Template (`sonicwall-analytics-panel.yaml`)

## Description
SonicWall Analytics (formerly SGMS) is SonicWall's centralised network security analytics and reporting platform used to aggregate and visualise threat data across SonicWall firewall deployments.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

