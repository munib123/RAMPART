# Vulnerability: /etc/hosts File Read/Write Check
**Classification:** LOCAL
**Source:** Nuclei Template (`rw-hosts-file.yaml`)

## Description
The /etc/hosts file was writable by non-root users, allowing attackers to register malicious DNS mappings and redirect legitimate domains (pharming attacks). This check verified that /etc/hosts was owned by root and had appropriate permissions.

