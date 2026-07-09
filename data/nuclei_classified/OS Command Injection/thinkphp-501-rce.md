# Nuclei Template: ThinkPHP 5.0.1 - Remote Code Execution
**Template ID:** thinkphp-501-rce
**Vulnerability Class:** OS Command Injection
**Severity:** Critical
**CWE:** CWE-78
**Source:** Nuclei Template (`thinkphp-501-rce.yaml`)

## Vulnerability Information & PoC

## Description
ThinkPHP 5.0.1 allows remote unauthenticated attackers to  execute arbitrary code via the 's' parameter.

## Steps to reproduce / Exploit Payload
```http
POST {{BaseURL}}/?s=index/index/index
```

## References
- https://www.exploit-db.com/exploits/46150
