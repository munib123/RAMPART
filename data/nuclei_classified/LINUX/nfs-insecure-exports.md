# Vulnerability: NFS Insecure Exports Check
**Classification:** LINUX
**Source:** Nuclei Template (`nfs-insecure-exports.yaml`)

## Description
Verified whether access control was properly configured on NFS.Highlighted possibilities such as allowing all hosts, no_root_squash, or unrestricted all_squash that could let unauthorized users access shared directories.

