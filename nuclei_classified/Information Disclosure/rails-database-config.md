# Nuclei Template: Ruby on Rails Database Configuration File - Detect
**Template ID:** rails-database-config
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`rails-database-config.yaml`)

## Vulnerability Information & PoC

## Description
Ruby on Rails database configuration file was detected, which may contain database credentials.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/config/database.yml
```

## References
- https://guides.rubyonrails.org/configuring.html#configuring-a-database
