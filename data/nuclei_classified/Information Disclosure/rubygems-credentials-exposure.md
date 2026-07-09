# Nuclei Template: Ruby Gem::ConfigFile Credential - Exposure
**Template ID:** rubygems-credentials-exposure
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`rubygems-credentials-exposure.yaml`)

## Vulnerability Information & PoC

## Description
Ruby Gem credentials file is exposed, potentially leaking RubyGems API keys. The ~/.gem/credentials file stores authentication tokens for publishing gems to RubyGems.org or private gem servers.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/.gem/credentials
GET {{BaseURL}}/credentials
GET {{BaseURL}}/.gem/credentials.yaml
```

## References
- https://guides.rubygems.org/rubygems-org-api/
- https://blog.rubygems.org/2020/07/28/api-key-leak.html
