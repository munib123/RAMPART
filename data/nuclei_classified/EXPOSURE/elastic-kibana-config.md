# Vulnerability: Elastic Kibana Config - File Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`elastic-kibana-config.yaml`)

## Description
Elastic Kibana Config file is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/kibana.yml
```

