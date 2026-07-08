# Vulnerability: Github pages config file
**Classification:** GITHUB
**Source:** Nuclei Template (`github-page-config.yaml`)

## Description
Find github pages config file.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/_config.yml
```

