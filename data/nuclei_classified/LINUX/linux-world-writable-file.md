# Vulnerability: Linux World-Writable File Permission
**Classification:** LINUX
**Source:** Nuclei Template (`linux-world-writable-file.yaml`)

## Description
System files were configured with world-writable (chmod o+w) permissions.Malicious users could modify them, leading to privilege escalation, backdoors, or service disruption.

