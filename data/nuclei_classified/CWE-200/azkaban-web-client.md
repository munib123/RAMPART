# Vulnerability: Azkaban Web Client
**Classification:** CWE-200
**Source:** Nuclei Template (`azkaban-web-client.yaml`)

## Description
An Azkaban web client panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

