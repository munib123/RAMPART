# Vulnerability: macOS World-Writable Launchd Jobs
**Classification:** MACOS
**Source:** Nuclei Template (`insecure-launchd-jobs.yaml`)

## Description
Searches for world-writable launchd job files on macOS that allow modification by any user.

## Secure Mitigation
Review and correct the permissions of world-writable launchd job files.

