# Vulnerability: Remote Spark Gateway Configuration/Credentials - Exposure
**Classification:** CWE-200
**Source:** Nuclei Template (`remote-spark-gateway-config.yaml`)

## Description
Remote Spark Gateway config found via /gateway.conf.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/gateway.conf
```

