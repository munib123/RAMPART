# Vulnerability: Springboot Actuator Metrics - Exposure
**Classification:** SPRINGBOOT
**Source:** Nuclei Template (`springboot-metrics.yaml`)

## Description
Spring Boot Metrics Actuator endpoint was detected, which may expose system metrics information. This template detects both older Spring Boot 1.x format and newer 2.x/3.x format.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/metrics
GET {{BaseURL}}/actuator/metrics
```

