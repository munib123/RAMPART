# Vulnerability: Github Gemfiles
**Classification:** GITHUB
**Source:** Nuclei Template (`github-gemfile-files.yaml`)

## Description
Find github page files(Gemfile / Gemfile.lock)

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Gemfile
GET {{BaseURL}}/Gemfile.lock
```

