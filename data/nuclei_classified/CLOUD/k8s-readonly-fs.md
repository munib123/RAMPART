# Vulnerability: Enforce Read-Only Filesystem for Containers
**Classification:** CLOUD
**Source:** Nuclei Template (`k8s-readonly-fs.yaml`)

## Description
Checks for containers that do not use a read-only filesystem, which can prevent malicious write operations at runtime

## Secure Mitigation
Configure containers to use read-only filesystems where possible to enhance security and minimize risk of unauthorized data modification

