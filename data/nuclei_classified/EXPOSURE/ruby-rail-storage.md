# Vulnerability: Ruby on Rails storage.yml File Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`ruby-rail-storage.yaml`)

## Description
Ruby on Rails storage.yml file is disclosed.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/storage.yml
GET {{BaseURL}}/config/storage.yml
GET {{BaseURL}}/ruby/config/storage.yml
GET {{BaseURL}}/railsapp/config/storage.yml
```

