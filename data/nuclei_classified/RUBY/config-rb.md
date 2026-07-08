# Vulnerability: Ruby Configuration File - Detect
**Classification:** RUBY
**Source:** Nuclei Template (`config-rb.yaml`)

## Description
Multiple Ruby configuration files were detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/config.rb
GET {{BaseURL}}/.chef/config.rb
GET {{BaseURL}}/assets/config.rb
```

