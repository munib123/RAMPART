# Vulnerability: ClamAV Server - Unauthenticated Access
**Classification:** NETWORK
**Source:** Nuclei Template (`clamav-unauth.yaml`)

## Description
ClamAV server 0.99.2, and possibly other previous versions, allow the execution
of dangerous service commands without authentication. Specifically, the command 'SCAN'
may be used to list system files and the command 'SHUTDOWN' shut downs the service.

