# Vulnerability: CouchDB - Default Login
**Classification:** CWE-522
**Source:** Nuclei Template (`couchdb-default-login.yaml`)

## Description
CouchDB weak admin credentials were discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /_session HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

name={{username}}&password={{password}}
```

