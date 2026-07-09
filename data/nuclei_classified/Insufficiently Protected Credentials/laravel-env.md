# Nuclei Template: Laravel - Sensitive Information Disclosure
**Template ID:** laravel-env
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`laravel-env.yaml`)

## Vulnerability Information & PoC

## Description
A Laravel .env file was discovered, which stores sensitive information like database credentials and tokens. It should not be publicly accessible.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}{{paths}}
```

## References
- https://laravel.com/docs/master/configuration#environment-configuration
- https://stackoverflow.com/questions/38331397/how-to-protect-env-file-in-laravel
