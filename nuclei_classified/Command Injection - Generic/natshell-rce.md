# Nuclei Template: NatShell Debug File - Remote Code Execution
**Template ID:** natshell-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`natshell-rce.yaml`)

## Vulnerability Information & PoC

## Description
The NatShell debug file is susceptible to a remote code execution vulnerability.

## Steps to reproduce / Exploit Payload
```http
POST {{BaseURL}}/debug.php
```

## References
- https://mp.weixin.qq.com/s/g4YNI6UBqIQcKL0TRkKWlw
