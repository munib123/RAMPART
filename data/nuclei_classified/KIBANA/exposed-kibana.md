# Vulnerability: Exposed Kibana
**Classification:** KIBANA
**Source:** Nuclei Template (`exposed-kibana.yaml`)

## Description
Kibana is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/app/kibana
GET {{BaseURL}}/app/kibana/
```

