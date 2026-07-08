# Vulnerability: Remote Desktop Listening Default Port - Detect
**Classification:** WINDOWS
**Source:** Nuclei Template (`remote-desktop-default-port.yaml`)

## Description
The Remote Desktop Protocol (RDP) service listens on a default port (TCP 3389), which is commonly targeted by attackers.

## Secure Mitigation
Change the default RDP listening port to a non-standard port to reduce exposure.

