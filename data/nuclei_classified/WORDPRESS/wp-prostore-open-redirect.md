# Vulnerability: WordPress ProStore <1.1.3 - Open Redirect
**Classification:** WORDPRESS
**Source:** Nuclei Template (`wp-prostore-open-redirect.yaml`)

## Description
WordPress ProStore theme before 1.1.3 contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/themes/prostore/go.php?https://interact.sh/
```

