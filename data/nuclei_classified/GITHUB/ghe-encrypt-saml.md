# Vulnerability: GitHub Enterprise - Encrypted SAML
**Classification:** GITHUB
**Source:** Nuclei Template (`ghe-encrypt-saml.yaml`)

## Description
This template checks if Encrypted SAML (Security Assertion Markup Language) is enabled on a GitHub Enterprise instance.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/saml/metadata
```

