# Vulnerability: Stytch API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-stytch.yaml`)

## Description
User infrastructure for modern applications

## Vulnerable Code Pattern / Exploit Payload
```http
POST https://test.stytch.com/v1/users HTTP/1.1
Authorization: Basic {{base64(id + ':' + secret)}}
Host: test.stytch.com
Content-Type: application/json

{"email": "test@stytch.com"}
```

