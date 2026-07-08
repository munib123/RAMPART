# Vulnerability: Daytime Service - Detect
**Classification:** DAYTIME
**Source:** Nuclei Template (`daytime-detect.yaml`)

## Description
Detects the Daytime service on UDP port 13 by requesting the current date and time in ASCII format as defined in RFC 867. This legacy protocol can expose system information and should be disabled to reduce attack surface.

