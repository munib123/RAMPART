# Vulnerability: Ruby on Rails Secret Token Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`rails-secret-token-disclosure.yaml`)

## Description
Ruby on Rals Secret Token file is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/config/initializers/secret_token.rb
```

