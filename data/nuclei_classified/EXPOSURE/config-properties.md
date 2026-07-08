# Vulnerability: Config Properties Exposure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`config-properties.yaml`)

## Description
Config Properties were exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/config.properties
GET {{BaseURL}}/config.properties.bak
GET {{BaseURL}}/ui_config.properties
```

