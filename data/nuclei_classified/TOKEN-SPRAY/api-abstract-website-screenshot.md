# Vulnerability: Abstract Api Website Screenshot Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-abstract-website-screenshot.yaml`)

## Description
Transform any URL into an image with Abstract's Website Screenshot API

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://screenshot.abstractapi.com/v1/?api_key={{token}}&url=https://test.test
```

