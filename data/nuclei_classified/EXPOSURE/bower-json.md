# Vulnerability: bower.json File Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`bower-json.yaml`)

## Description
Bower is a package manager which stores package information in the bower.json file

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/bower.json
```

