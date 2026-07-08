# Vulnerability: /etc/services Permission Check
**Classification:** LINUX
**Source:** Nuclei Template (`etc-services-permission-check.yaml`)

## Description
The /etc/services file was not owned by root or had excessive permissions,allowing attackers to alter port assignments to redirect services or open unauthorized ports.

