# Vulnerability: Generic Env File Disclosure
**Classification:** CWE-552
**Source:** Nuclei Template (`generic-env.yaml`)

## Description
A .env file was discovered containing sensitive information like database credentials and tokens. It should not be publicly accessible.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}{{paths}}
```

