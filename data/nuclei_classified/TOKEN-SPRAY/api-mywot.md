# Vulnerability: My Web of Trust API
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-mywot.yaml`)

## Description
IP/domain/URL reputation

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://scorecard.api.mywot.com/v3/targets?t=hbo.com&t=google.com HTTP/1.1
Host: scorecard.api.mywot.com
x-user-id: {{id}}
x-api-key: {{token}}
```

