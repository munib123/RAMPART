# Vulnerability: Shutdown on Audit Failure Check
**Classification:** ACCOUNT-MANAGEMENT
**Source:** Nuclei Template (`crash-on-audit-fail.yaml`)

## Description
Ensure the "Shutdown on Audit Failure" policy is disabled.
The registry value should be set to "4,0" to prevent the system from shutting down if it cannot log security audit events.
If set to "4,1", the system will shut down on audit failure, which could result in a denial-of-service condition.

## Secure Mitigation
Disable the policy by setting the CrashOnAuditFail value to "4,0". This can be done by:
- Using the Registry Editor: Navigate to HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System and set CrashOnAuditFail to "4,0".
- Through Local Security Policy: Set "Audit: Shut down system immediately if unable to log security audits" to Disabled.

