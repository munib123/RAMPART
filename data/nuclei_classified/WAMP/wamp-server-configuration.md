# Vulnerability: default-wamp-server-page
**Classification:** WAMP
**Source:** Nuclei Template (`wamp-server-configuration.yaml`)

## Description
Wamp default page will expose sensitive configuration and vhosts.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

