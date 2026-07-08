# Vulnerability: Apache Kyuubi - Configuration Exposure
**Classification:** CONFIG
**Source:** Nuclei Template (`apache-kyuubi-config.yaml`)

## Description
Detects if path Appconfigs of Apache Kyuubi web application is exposed, getting internal information about the configuration made.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/engine-ui/0.0.0.0:4040/environment/
```

