# Vulnerability: Root SUID/SGID File Check
**Classification:** LINUX
**Source:** Nuclei Template (`suid-sgid.yaml`)

## Description
Files owned by root with SUID or SGID permissions could have led to privilege escalation.if misconfigured. This template detected such files for further review.

