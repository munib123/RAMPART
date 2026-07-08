# Vulnerability: macOS World-Writable Cron Jobs
**Classification:** MACOS
**Source:** Nuclei Template (`insecure-cron-jobs.yaml`)

## Description
Finds world-writable cron job files on macOS that can be modified by any user on the system.

## Secure Mitigation
Review and correct the permissions of world-writable cron job files.

