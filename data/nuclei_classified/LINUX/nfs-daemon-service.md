# Vulnerability: NFS Service Daemon Should Be Disabled
**Classification:** LINUX
**Source:** Nuclei Template (`nfs-daemon-service.yaml`)

## Description
Assessed the status of the NFS service daemon. A running NFS service may expose the system to unauthorized access, modification, or deletion of files; it is recommended to disable the daemon when not explicitly required.

