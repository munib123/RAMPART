# Vulnerability: Clearbit API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-clearbit.yaml`)

## Description
Search for company logos and embed them in your projects

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://person.clearbit.com/v2/combined/find?email=alex@clearbit.com HTTP/1.1
Authorization: Basic {{base64(token + ':')}}
Host: person.clearbit.com
```

