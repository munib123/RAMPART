# Vulnerability: WordPress Weekender Newspaper 9.0 - Open Redirect
**Classification:** CWE-601
**Source:** Nuclei Template (`weekender-newspaper-open-redirect.yaml`)

## Description
WordPress Weekender Newspaper theme 9.0 contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/wp-content/themes/weekender/friend.php?id=aHR0cHM6Ly9pbnRlcmFjdC5zaA==
```

