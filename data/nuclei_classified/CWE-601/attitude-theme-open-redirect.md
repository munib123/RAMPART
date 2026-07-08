# Vulnerability: WordPress Attitude 1.1.1 - Open Redirect
**Classification:** CWE-601
**Source:** Nuclei Template (`attitude-theme-open-redirect.yaml`)

## Description
WordPress Attitude theme 1.1.1 contains an open redirect vulnerability via the goto.php endpoint. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/themes/Attitude/go.php?https://interact.sh/
```

