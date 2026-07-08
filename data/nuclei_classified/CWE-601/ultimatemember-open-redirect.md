# Vulnerability: WordPress Ultimate Member <2.1.7 - Open Redirect
**Classification:** CWE-601
**Source:** Nuclei Template (`ultimatemember-open-redirect.yaml`)

## Description
WordPress Ultimate Member plugin before 2.1.7 contains an open redirect vulnerability on the registration and login pages via the "redirect_to" GET parameter. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Secure Mitigation
Fixed in 2.1.7.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/register/?redirect_to=https://interact.sh/
```

