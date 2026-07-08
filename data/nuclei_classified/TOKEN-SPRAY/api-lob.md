# Vulnerability: Lob API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-lob.yaml`)

## Description
US Address Verification

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.lob.com/v1/addresses HTTP/1.1
Authorization: Basic {{base64(token + ':')}}
Host: api.lob.com
```

