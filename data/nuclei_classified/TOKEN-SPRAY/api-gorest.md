# Vulnerability: Gorest API Test
**Classification:** TOKEN-SPRAY
**Source:** Nuclei Template (`api-gorest.yaml`)

## Description
Online REST API for Testing and Prototyping

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://gorest.co.in/public/v2/users HTTP/1.1
Host: gorest.co.in
Content-Type: application/json
Authorization: Bearer {{token}}

{"name":"Tenali Ramakrishna", "gender":"male", "email":"tenali.rdamakrishna@15ce.com", "status":"active"}
```

