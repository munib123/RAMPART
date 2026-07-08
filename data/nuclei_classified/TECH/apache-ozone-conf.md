# Vulnerability: Apache Ozone - Exposure
**Classification:** TECH
**Source:** Nuclei Template (`apache-ozone-conf.yaml`)

## Description
Detects if path /conf of Apache Ozone web application is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/conf
```

