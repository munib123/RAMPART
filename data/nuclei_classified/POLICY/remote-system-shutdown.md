# Vulnerability: Remote System Forced Shutdown Privilege Check
**Classification:** POLICY
**Source:** Nuclei Template (`remote-system-shutdown.yaml`)

## Description
Ensure the "Force shutdown from a remote system" policy (SeRemoteShutdownPrivilege) is assigned only to the Administrators group (SID: S-1-5-32-544). Granting this privilege to unauthorized accounts can allow attackers to remotely shut down the system, posing a significant risk.

## Secure Mitigation
Configure the policy to grant the SeRemoteShutdownPrivilege exclusively to the Administrators group by setting its value to S-1-5-32-544 only.

