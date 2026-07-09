# Nuclei Template: Netdisco Admin - Default Login
**Template ID:** netdisco-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** Critical
**Source:** Nuclei Template (`netdisco-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Detects use of hard-coded credentials in Netdisco.

## Impact
Attackers can potentially exploit this vulnerability to gain unauthorized access to sensitive information.

## Steps to reproduce / Exploit Payload
```http
POST /login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

username={{username}}&password={{password}}&return_url=%2Finventory
```

## Remediation
Update the application to remove hard-coded credentials and implement secure credential management practices.

