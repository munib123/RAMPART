# Vulnerability: Exposed Cobbler Directories
**Classification:** COBBLER
**Source:** Nuclei Template (`cobbler-exposed-directory.yaml`)

## Description
Searches for exposed Cobbler Directories

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cobbler/
GET {{BaseURL}}/cblr/
```

