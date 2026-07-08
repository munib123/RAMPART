# Vulnerability: Apache Hive Configuration - Exposure
**Classification:** APACHE
**Source:** Nuclei Template (`apache-hive-config.yaml`)

## Description
Detects if the config page of the Apache Hive is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/conf
```

