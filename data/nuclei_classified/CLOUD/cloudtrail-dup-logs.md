# Vulnerability: CloudTrail Duplicate Log Avoidance
**Classification:** CLOUD
**Source:** Nuclei Template (`cloudtrail-dup-logs.yaml`)

## Description
Ensure CloudTrail logging is configured to prevent duplicate recording of global service events across multiple trails.

## Secure Mitigation
Configure only one multi-region trail to log global service events and disable global service logging for all other trails.

