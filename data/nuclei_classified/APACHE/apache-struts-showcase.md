# Vulnerability: Apache Struts - ShowCase Application Exposure
**Classification:** APACHE
**Source:** Nuclei Template (`apache-struts-showcase.yaml`)

## Description
Apache Structs ShowCase Application is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/struts2-showcase/showcase.action
```

