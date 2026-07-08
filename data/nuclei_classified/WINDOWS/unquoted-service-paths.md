# Vulnerability: Unquoted Service Paths
**Classification:** WINDOWS
**Source:** Nuclei Template (`unquoted-service-paths.yaml`)

## Description
Detects windows services with unquoted paths that contain spaces. This misconfiguration can lead to local privilege escalation via execution of a malicious binary placed in the path.

