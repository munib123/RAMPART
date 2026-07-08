# Vulnerability: Ruby Gem::ConfigFile Credential - Exposure
**Classification:** CWE-200
**Source:** Nuclei Template (`rubygems-credentials-exposure.yaml`)

## Description
Ruby Gem credentials file is exposed, potentially leaking RubyGems API keys. The ~/.gem/credentials file stores authentication tokens for publishing gems to RubyGems.org or private gem servers.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/.gem/credentials
GET {{BaseURL}}/credentials
GET {{BaseURL}}/.gem/credentials.yaml
```

