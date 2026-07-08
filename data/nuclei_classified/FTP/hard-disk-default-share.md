# Vulnerability: Hard Disk Default Share Removal Check
**Classification:** FTP
**Source:** Nuclei Template (`hard-disk-default-share.yaml`)

## Description
Ensure default administrative shares (e.g., C$, D$, Admin$) are disabled by verifying that the AutoShareServer registry value is set to 0.
Leaving these shares enabled can expose system resources to unauthorized access.

## Secure Mitigation
Permanently disable default administrative shares by setting the AutoShareServer registry value to 0 at:
- HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters
- Additionally, remove any non-essential default shares using the appropriate system management tools.

