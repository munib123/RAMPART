# Nuclei Template: ThinkPHP 5.0.23 - Remote Code Execution
**Template ID:** thinkphp-5023-rce
**Vulnerability Class:** Code Injection
**Severity:** Critical
**CWE:** CWE-95
**Source:** Nuclei Template (`thinkphp-5023-rce.yaml`)

## Vulnerability Information & PoC

## Description
ThinkPHP 5.0.23 is susceptible to remote code execution. An attacker can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.

## Steps to reproduce / Exploit Payload
```http
POST {{BaseURL}}/index.php?s=captcha
```

## References
- https://github.com/vulhub/vulhub/tree/0a0bc719f9a9ad5b27854e92bc4dfa17deea25b4/thinkphp/5.0.23-rce
