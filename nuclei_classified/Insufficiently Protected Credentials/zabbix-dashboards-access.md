# Nuclei Template: zabbix-dashboards-access
**Template ID:** zabbix-dashboards-access
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** Medium
**CWE:** CWE-522
**Source:** Nuclei Template (`zabbix-dashboards-access.yaml`)

## Vulnerability Information & PoC

## Description
zabbix-dashboards-access guest login credentials were successful.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/zabbix/zabbix.php?action=dashboard.list
```

## References
- https://www.exploit-db.com/ghdb/5595
- https://packetstormsecurity.com/files/163657/zabbix5x-sqlxss.txt
