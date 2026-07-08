# Vulnerability: China Unicom Modem Default Login
**Classification:** CWE-798
**Source:** Nuclei Template (`chinaunicom-default-login.yaml`)

## Description
Default login credentials were discovered for a China Unicom modem.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /cu.html HTTP/1.1
Host: {{Hostname}}

frashnum=&action=login&Frm_Logintoken=1&Username={{username}}&Password={{password}}&Username=&Password=
```

