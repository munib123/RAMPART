# Vulnerability: Ensure NIS Client is Not Installed
**Classification:** CIS
**Source:** Nuclei Template (`nis-client.yaml`)

## Description
The nis package provides the Network Information Service client, which is insecure and deprecated.If not explicitly required, it should be removed to reduce the system’s attack surface.

## Secure Mitigation
- Ensure the nis package is not installed unless explicitly required.
- To remove the package, run: sudo apt-get remove nis -y

