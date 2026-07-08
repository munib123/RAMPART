# Vulnerability: Open Virtualization Manager Detection
**Classification:** CWE-200
**Source:** Nuclei Template (`open-virtualization-manager-detect.yaml`)

## Description
Open Virtualization Manager was detected. Open Virtualization Manager is an open-source distributed virtualization solution designed to manage enterprise infrastructure. oVirt uses the trusted KVM hypervisor and is built upon several other community projects, including libvirt, Gluster, PatternFly, and Ansible.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ovirt-engine/
```

