# Vulnerability: Cloudfoundry Detect
**Classification:** CLOUDFOUNDRY
**Source:** Nuclei Template (`cloudfoundry-detect.yaml`)

## Description
Detects cloudfoundry based on response headers

## Vulnerable Code Pattern / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

GET / HTTP/1.1
Host: {{randstr}}.com
```

