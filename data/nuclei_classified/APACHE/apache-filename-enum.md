# Vulnerability: Apache Filename Enumeration
**Classification:** APACHE
**Source:** Nuclei Template (`apache-filename-enum.yaml`)

## Description
If the client provides an invalid Accept header, the server will respond with a 406 Not Acceptable error containing a pseudo directory listing.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/index
```

