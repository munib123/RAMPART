# Vulnerability: Remote Registry Service Disabled Check
**Classification:** CODE
**Source:** Nuclei Template (`remote-registry-access-check.yaml`)

## Description
Ensure the Remote Registry Service is disabled to block remote access to the Windows registry. Allowing remote registry access can lead to unauthorized changes and pose a serious security risk.

## Secure Mitigation
Disable the Remote Registry Service by setting its startup type to "Disabled" (Start value = 4) using one of the following methods:
- Registry Editor: Navigate to
   - HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\RemoteRegistry and set the Start value to 4.
    - Services Console: Locate the Remote Registry service, set its startup type to "Disabled", and stop the service.

