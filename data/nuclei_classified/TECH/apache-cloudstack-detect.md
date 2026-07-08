# Vulnerability: Apache CloudStack - Detect
**Classification:** TECH
**Source:** Nuclei Template (`apache-cloudstack-detect.yaml`)

## Description
CloudStack is open-source Infrastructure-as-a-Service cloud computing software for creating, managing, and deploying infrastructure cloud services. It uses existing hypervisor platforms for virtualization, such as KVM, VMware vSphere, including ESXi and vCenter, XenServer/XCP and XCP-ng.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

