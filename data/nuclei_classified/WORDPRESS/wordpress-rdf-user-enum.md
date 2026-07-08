# Vulnerability: Wordpress RDF User Enumeration
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wordpress-rdf-user-enum.yaml`)

## Description
Leaked Wordpress RDF leads to User Emumeration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/feed/rdf
```

