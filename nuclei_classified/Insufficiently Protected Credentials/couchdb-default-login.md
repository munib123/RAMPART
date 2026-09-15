# Nuclei Template: CouchDB - Default Login
**Template ID:** couchdb-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`couchdb-default-login.yaml`)

## Vulnerability Information & PoC

## Description
CouchDB weak admin credentials were discovered.

## Steps to reproduce / Exploit Payload
```http
POST /_session HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

name={{username}}&password={{password}}
```

