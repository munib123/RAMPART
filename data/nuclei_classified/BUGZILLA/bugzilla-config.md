# Vulnerability: Bugzilla - Config Exposed
**Classification:** BUGZILLA
**Source:** Nuclei Template (`bugzilla-config.yaml`)

## Description
Because the config.cgi is publicly exposed, it is possible to enumerate main domain and possible users registered on Bugzilla server.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/config.cgi
```

