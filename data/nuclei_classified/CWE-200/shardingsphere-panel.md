# Vulnerability: ShardingSphere ElasticJob UI Panel
**Classification:** CWE-200
**Source:** Nuclei Template (`shardingsphere-panel.yaml`)

## Description
An ShardingSphere ElasticJob UI panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/#/login
```

