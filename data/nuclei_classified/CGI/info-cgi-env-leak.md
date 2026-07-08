# Vulnerability: info.cgi  Environment Variable - Disclosure
**Classification:** CGI
**Source:** Nuclei Template (`info-cgi-env-leak.yaml`)

## Description
Detected exposure of server environment variables through the info.cgi script. This can leak sensitive paths, internal IPs, software versions, credentials in env, etc.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/info.cgi
GET {{BaseURL}}/cgi-bin/info.cgi
GET {{BaseURL}}/cgi-sys/info.cgi
GET {{BaseURL}}/scripts/info.cgi
GET {{BaseURL}}/lite-scripts/info.cgi
```

