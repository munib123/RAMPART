# Vulnerability: Apache Detection
**Classification:** TECH
**Source:** Nuclei Template (`apache-detect.yaml`)

## Description
Some Apache servers have the version on the response header. The OpenSSL version can be also obtained

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

