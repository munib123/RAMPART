# Vulnerability: Laravel - Sensitive Information Disclosure
**Classification:** CWE-522
**Source:** Nuclei Template (`laravel-env.yaml`)

## Description
A Laravel .env file was discovered, which stores sensitive information like database credentials and tokens. It should not be publicly accessible.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}{{paths}}
```

