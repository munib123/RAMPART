# Vulnerability: WordPress eCommerce Music Store <=1.0.14 - Open Redirect
**Classification:** CWE-601
**Source:** Nuclei Template (`music-store-open-redirect.yaml`)

## Description
WordPress eCommerce Music Store plugin through 1.0.14 contains an open redirect vulnerability via the referer header. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /wp-content/plugins/music-store/ms-core/ms-submit.php HTTP/1.1
Host: {{Hostname}}
Referer: https://interact.sh
```

