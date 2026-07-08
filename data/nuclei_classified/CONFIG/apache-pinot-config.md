# Vulnerability: Apache Pinot - Exposure
**Classification:** CONFIG
**Source:** Nuclei Template (`apache-pinot-config.yaml`)

## Description
Detects if path Appconfigs of Apache Pinot web application is exposed, getting internal information about the configuration made.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/appconfigs
```

