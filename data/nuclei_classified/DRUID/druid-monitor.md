# Vulnerability: Alibaba Druid Monitor Unauthorized Access
**Classification:** DRUID
**Source:** Nuclei Template (`druid-monitor.yaml`)

## Description
Alibaba Druid Monitor is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/druid/index.html
```

