# Vulnerability: zabbix-dashboards-access
**Classification:** CWE-522
**Source:** Nuclei Template (`zabbix-dashboards-access.yaml`)

## Description
zabbix-dashboards-access guest login credentials were successful.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/zabbix/zabbix.php?action=dashboard.list
```

