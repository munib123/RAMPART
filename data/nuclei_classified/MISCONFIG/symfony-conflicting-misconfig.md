# Vulnerability: Symfony Conflicting Headers - Information Disclosure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`symfony-conflicting-misconfig.yaml`)

## Description
A misconfiguration in Symfony’s trusted proxy and header settings could trigger a ConflictingHeadersException when both Forwarded and X-Forwarded-* headers were present. When debug mode was enabled in production, this issue could have exposed sensitive environment details such as SMTP credentials, application paths, or system configuration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

