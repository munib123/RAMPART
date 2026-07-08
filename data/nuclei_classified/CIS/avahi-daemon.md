# Vulnerability: Ensure Avahi Daemon Service is Not Installed
**Classification:** CIS
**Source:** Nuclei Template (`avahi-daemon.yaml`)

## Description
The avahi-daemon package provides mDNS/DNS-SD service discovery on local networks.In secure environments, it should only be installed when explicitly required, as it may expose unnecessary services.

## Secure Mitigation
- Ensure the `avahi-daemon` package is not installed unless explicitly required.
- To remove the package, run: sudo apt-get remove avahi-daemon -y

