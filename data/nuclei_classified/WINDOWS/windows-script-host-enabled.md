# Vulnerability: Windows Script Host Enabled
**Classification:** WINDOWS
**Source:** Nuclei Template (`windows-script-host-enabled.yaml`)

## Description
Checks if Windows Script Host is enabled, which can be used to run malicious scripts.

## Secure Mitigation
Disable Windows Script Host by setting the Enabled registry key to 0.

