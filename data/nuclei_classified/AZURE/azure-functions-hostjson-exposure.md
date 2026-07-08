# Vulnerability: Azure Functions host.json Configuration Exposure
**Classification:** AZURE
**Source:** Nuclei Template (`azure-functions-hostjson-exposure.yaml`)

## Description
Detected exposed Azure Functions host.json configuration files. The exposed metadata revealed sensitive runtime, logging, extension, and infrastructure settings that could aid attackers in understanding the application architecture.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/host.json
```

