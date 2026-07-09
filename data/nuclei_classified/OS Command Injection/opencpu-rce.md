# Nuclei Template: OpenCPU - Remote Code Execution
**Template ID:** opencpu-rce
**Vulnerability Class:** OS Command Injection
**Severity:** Critical
**CWE:** CWE-78
**Source:** Nuclei Template (`opencpu-rce.yaml`)

## Vulnerability Information & PoC

## Description
Check for remote code execution via OpenCPU was conducted.

## Steps to reproduce / Exploit Payload
```http
POST {{BaseURL}}/ocpu/library/base/R/do.call/json
```

## References
- https://pulsesecurity.co.nz/articles/R-Shells
- https://github.com/opencpu/opencpu/
