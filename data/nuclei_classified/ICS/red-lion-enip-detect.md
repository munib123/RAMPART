# Vulnerability: Red Lion ENIP - Detect
**Classification:** ICS
**Source:** Nuclei Template (`red-lion-enip-detect.yaml`)

## Description
Detects Red Lion industrial control devices by sending Ethernet/IP (ENIP) protocol requests to port 789 and identifying devices that respond with "Red Lion Controls" in their response. This template can be used to discover and fingerprint Red Lion devices on industrial networks.

