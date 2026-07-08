# Vulnerability: Apache Hbase Unauth
**Classification:** APACHE
**Source:** Nuclei Template (`apache-hbase-unauth.yaml`)

## Description
Apache Hbase is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/conf
```

