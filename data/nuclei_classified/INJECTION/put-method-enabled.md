# Vulnerability: PUT Method Enabled
**Classification:** INJECTION
**Source:** Nuclei Template (`put-method-enabled.yaml`)

## Description
The HTTP PUT method is normally used to upload data that is saved on the server at a user-supplied URL. If enabled, an attacker may be able to place arbitrary, and potentially malicious, content into the application. Depending on the server's configuration, this may lead to compromise of other users (by uploading client-executable scripts), compromise of the server (by uploading server-executable code), or other attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
PUT /testing-put.txt HTTP/1.1
Host: {{Hostname}}
Content-Type: text/plain

{{randstr}}

GET /testing-put.txt HTTP/1.1
Host: {{Hostname}}
Content-Type: text/plain
```

