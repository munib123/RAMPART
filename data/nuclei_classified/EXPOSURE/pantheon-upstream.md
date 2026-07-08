# Vulnerability: Pantheon upstream.yml Disclosure
**Classification:** EXPOSURE
**Source:** Nuclei Template (`pantheon-upstream.yaml`)

## Description
Public Pantheon YAML Configuration Files might include sensitive info

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/pantheon.upstream.yml
```

