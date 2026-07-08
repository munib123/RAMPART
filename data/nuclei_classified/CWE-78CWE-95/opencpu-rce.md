# Vulnerability: OpenCPU - Remote Code Execution
**Classification:** CWE-78,CWE-95
**Source:** Nuclei Template (`opencpu-rce.yaml`)

## Description
Check for remote code execution via OpenCPU was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
POST {{BaseURL}}/ocpu/library/base/R/do.call/json
```

