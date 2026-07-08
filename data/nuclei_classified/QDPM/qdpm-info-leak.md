# Vulnerability: qdPM 9.2 - DB Credentials Exposure
**Classification:** QDPM
**Source:** Nuclei Template (`qdpm-info-leak.yaml`)

## Description
qdPM 9.2 database credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/core/config/databases.yml
```

