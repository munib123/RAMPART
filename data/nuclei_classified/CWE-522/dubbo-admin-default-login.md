# Vulnerability: Apache Dubbo - Default Admin Discovery
**Classification:** CWE-522
**Source:** Nuclei Template (`dubbo-admin-default-login.yaml`)

## Description
Apache Dubbo default admin credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/
```

