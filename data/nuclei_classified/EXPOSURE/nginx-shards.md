# Vulnerability: NGINX Shards Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`nginx-shards.yaml`)

## Description
NGINX internal information, shards page exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/static/shards.html
GET {{BaseURL}}/static/shards/html
```

