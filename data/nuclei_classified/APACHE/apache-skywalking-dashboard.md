# Vulnerability: Apache SkyWalking - Dashboard
**Classification:** APACHE
**Source:** Nuclei Template (`apache-skywalking-dashboard.yaml`)

## Description
Apache SkyWalking server, an APM, Application Performance Monitoring System, exposed the backend monitoring dashboard. An attacker can execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /dashboard/list HTTP/1.1
Host: {{Hostname}}
```

