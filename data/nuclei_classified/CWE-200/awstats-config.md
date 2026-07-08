# Vulnerability: AWStats Config - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`awstats-config.yaml`)

## Description
AWStats configuration information was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/awstats/
GET {{BaseURL}}/awstats.conf
```

