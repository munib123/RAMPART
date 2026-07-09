# Nuclei Template: CouchDB Admin Default - Detect
**Template ID:** couchdb-adminparty
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`couchdb-adminparty.yaml`)

## Vulnerability Information & PoC

## Description
CouchDB is susceptible to requests in the context of an admin user.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/_users/_all_docs
```

## References
- https://docs.couchdb.org/en/stable/intro/security.html#authentication-database
