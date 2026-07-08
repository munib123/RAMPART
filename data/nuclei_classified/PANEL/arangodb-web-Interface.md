# Vulnerability: ArangoDB Web Interface - Detect
**Classification:** PANEL
**Source:** Nuclei Template (`arangodb-web-Interface.yaml`)

## Description
ArangoDB Web Interface was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/_db/_system/_admin/aardvark/index.html
```

