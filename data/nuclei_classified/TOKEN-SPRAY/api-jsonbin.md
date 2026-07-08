# Vulnerability: JSONBin API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-jsonbin.yaml`)

## Description
Free JSON storage service. Ideal for small scale Web apps, Websites and Mobile apps

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.jsonbin.io/v3/c HTTP/1.1
Host: api.jsonbin.io
X-Master-key: {{token}}
```

