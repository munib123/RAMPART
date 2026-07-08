# Vulnerability: macOS SUID/SGID Files Detection
**Classification:** MACOS
**Source:** Nuclei Template (`suid-sgid-files.yaml`)

## Description
Discovers files with SUID or SGID permissions in user-writable directories (/usr/local, /opt, /Applications) that could be exploited for privilege escalation if misconfigured or vulnerable.

## Secure Mitigation
Review the list of SUID/SGID files and remove the permissions if they are not necessary.

