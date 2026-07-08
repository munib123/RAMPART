# Vulnerability: Petfinder API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-petfinder.yaml`)

## Description
Petfinder is dedicated to helping pets find homes, another resource to get pets adopted

## Vulnerable Code Pattern / Exploit Payload
```http
POST https://api.petfinder.com/v2/oauth2/token HTTP/1.1
Host: api.petfinder.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 81

grant_type=client_credentials&client_id={{id}}&client_secret={{secret}}
```

