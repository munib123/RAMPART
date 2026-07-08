# Vulnerability: Google Chromecast - Detect
**Classification:** GOOGLE
**Source:** Nuclei Template (`chromecast-detect.yaml`)

## Description
Searches for Google Chromecast via their eureka_info route.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /setup/eureka_info HTTP/1.1
Host: {{Hostname}}
```

