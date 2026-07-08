# Vulnerability: SAM File Access Control Check
**Classification:** SAM
**Source:** Nuclei Template (`sam-file-access-control.yaml`)

## Description
Ensure the SAM file (%SystemRoot%\system32\config\SAM) is secured so that only the Administrators and SYSTEM groups have full access.The presence of permissions for any other users or groups represents a potential security vulnerability.

## Secure Mitigation
Revoke any permissions assigned to users or groups other than Administrators and SYSTEM by:
- Running the command: > cacls %systemroot%\system32\config\SAM /remove:g [UserOrGroup]
- Or by adjusting the permissions through File Explorer.

