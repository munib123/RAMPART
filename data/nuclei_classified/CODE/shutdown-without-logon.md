# Vulnerability: Shutdown Without Logon Check
**Classification:** CODE
**Source:** Nuclei Template (`shutdown-without-logon.yaml`)

## Description
Ensure the "Shutdown Without Logon" policy is disabled by confirming that the ShutdownWithoutLogon registry value is set to 0. If enabled, the system permits shutdown from the logon screen, increasing the risk of unauthorized shutdowns.

## Secure Mitigation
Disable this policy by setting the ShutdownWithoutLogon registry value to 0 at:
- HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System
- Alternatively, configure the setting through the Local Security Policy.

