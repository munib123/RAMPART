# Vulnerability: Apache ActiveMQ Exposure
**Classification:** CWE-200
**Source:** Nuclei Template (`activemq-panel.yaml`)

## Description
An Apache ActiveMQ implementation was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/admin/
GET {{BaseURL}}/demo/
GET {{BaseURL}}
```

