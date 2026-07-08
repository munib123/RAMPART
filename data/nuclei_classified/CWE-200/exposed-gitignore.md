# Vulnerability: Gitignore Config - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`exposed-gitignore.yaml`)

## Description
Gitignore configuration information was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.gitignore
GET {{BaseURL}}/assets/.gitignore
GET {{BaseURL}}/includes/.gitignore
```

