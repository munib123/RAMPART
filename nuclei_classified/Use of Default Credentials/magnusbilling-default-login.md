# Nuclei Template: MagnusBilling - Default Login
**Template ID:** magnusbilling-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`magnusbilling-default-login.yaml`)

## Vulnerability Information & PoC

## Description
MagnusBilling installs with a default administrative account using the credentials root / magnus. If unchanged, these credentials grant full access to the system, allowing attackers to manage billing data, modify configurations, and potentially execute arbitrary code or commands via exposed interfaces.

## Impact
An unauthenticated attacker can gain full administrative control over the MagnusBilling platform, leading to compromise of billing systems, data leakage, and potential pivoting into internal infrastructure.

## Steps to reproduce / Exploit Payload
```http
POST /mbilling/index.php/authentication/login HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

user={{username}}&password={{password}}&key=
```

