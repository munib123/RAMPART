# Vulnerability: Open Virtualization Userportal & Webadmin Panel Detection
**Classification:** CWE-668
**Source:** Nuclei Template (`open-virtualization-manager-panel.yaml`)

## Description
Open Virtualization Userportal & Webadmin panels were detected. Open Virtualization Manager is an open-source distributed virtualization solution designed to manage enterprise infrastructure. oVirt uses the trusted KVM hypervisor and is built upon several other community projects, including libvirt, Gluster, PatternFly, and Ansible.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ovirt-engine/userportal/
GET {{BaseURL}}/ovirt-engine/webadmin/
```

