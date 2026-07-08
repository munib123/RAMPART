# Vulnerability: Putty Private Key Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`putty-private-key-disclosure.yaml`)

## Description
Putty internal user key file is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/my.ppk
GET {{BaseURL}}/putty.ppk
GET {{BaseURL}}/{{Hostname}}.ppk
GET {{BaseURL}}/.ssh/putty.ppk
GET {{BaseURL}}/.ssh/{{Hostname}}.ppk
GET {{BaseURL}}/.putty/my.ppk
GET {{BaseURL}}/.putty/putty.ppk
GET {{BaseURL}}/.putty/{{Hostname}}.ppk
```

