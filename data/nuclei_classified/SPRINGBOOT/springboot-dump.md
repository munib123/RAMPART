# Vulnerability: Detect Springboot Dump Actuator
**Classification:** SPRINGBOOT
**Source:** Nuclei Template (`springboot-dump.yaml`)

## Description
Performs a thread dump

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/dump
GET {{BaseURL}}/actuator/dump
```

