# Vulnerability: Detect Springboot autoconfig Actuator
**Classification:** SPRINGBOOT
**Source:** Nuclei Template (`springboot-autoconfig.yaml`)

## Description
Displays an auto-configuration report showing all auto-configuration candidates and the reason why they 'were' or 'were not' applied.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/autoconfig
GET {{BaseURL}}/actuator/autoconfig
```

