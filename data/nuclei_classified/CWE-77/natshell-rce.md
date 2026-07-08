# Vulnerability: NatShell Debug File - Remote Code Execution
**Classification:** CWE-77
**Source:** Nuclei Template (`natshell-rce.yaml`)

## Description
The NatShell debug file is susceptible to a remote code execution vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
POST {{BaseURL}}/debug.php
```

