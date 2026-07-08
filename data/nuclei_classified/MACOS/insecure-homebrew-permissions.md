# Vulnerability: macOS World-Writable Homebrew Files
**Classification:** MACOS
**Source:** Nuclei Template (`insecure-homebrew-permissions.yaml`)

## Description
Scans for world-writable files in the Homebrew directory that could be exploited for privilege escalation.

## Secure Mitigation
Review and correct the permissions of world-writable files in the Homebrew directory.

