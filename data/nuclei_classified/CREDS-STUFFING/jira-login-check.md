# Vulnerability: Jira Login Check
**Classification:** CREDS-STUFFING
**Source:** Nuclei Template (`jira-login-check.yaml`)

## Description
Checks for a valid login on self hosted Jira instance.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /rest/gadget/1.0/login HTTP/1.1
Host: {{Hostname}}
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Connection: close

os_username={{username}}&os_password={{password}}
```

