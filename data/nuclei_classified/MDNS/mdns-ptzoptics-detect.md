# Vulnerability: PTZOptics Device via mDNS - Detect
**Classification:** MDNS
**Source:** Nuclei Template (`mdns-ptzoptics-detect.yaml`)

## Description
Detects PTZOptics camera devices exposed via mDNS (Multicast DNS) on port 5353. PTZOptics cameras broadcast mDNS service advertisements including SSH, SFTP, and NDI streaming services. These devices are commonly used for video conferencing and broadcast production.

