# Vulnerability: WordPress Plugin Ultimate Member
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wp-plugin-utlimate-member.yaml`)

## Description
Searches for sensitive directories present in the ultimate-member plugin.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/plugins/ultimate-member/
```

