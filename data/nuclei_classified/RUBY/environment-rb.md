# Vulnerability: Environment Ruby File Disclosure
**Classification:** RUBY
**Source:** Nuclei Template (`environment-rb.yaml`)

## Description
Ruby environment file is exposed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/environment.rb
GET {{BaseURL}}/config/environment.rb
GET {{BaseURL}}/redmine/config/environment.rb
```

