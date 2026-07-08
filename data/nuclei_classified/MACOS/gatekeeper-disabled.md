# Vulnerability: macOS Gatekeeper Disabled
**Classification:** MACOS
**Source:** Nuclei Template (`gatekeeper-disabled.yaml`)

## Description
Checks if Gatekeeper is disabled on macOS, removing verification that downloaded applications are from identified developers.

## Secure Mitigation
Enable Gatekeeper to ensure that only applications from identified developers can be run.

