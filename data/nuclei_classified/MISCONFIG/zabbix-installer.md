# Vulnerability: Zabbix Installation Exposure
**Classification:** MISCONFIG
**Source:** Nuclei Template (`zabbix-installer.yaml`)

## Description
Zabbix is susceptible to the Installation page exposure due to misconfiguration.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/setup.php
```

