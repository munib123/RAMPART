# Vulnerability: Ensure rsh Client is Not Installed
**Classification:** CIS
**Source:** Nuclei Template (`rsh-client.yaml`)

## Description
The rsh-client package provides the Remote Shell client, which transmits data in plaintext and is considered insecure.If not explicitly required, it should be removed to reduce exposure to unauthorized remote access.

## Secure Mitigation
Ensure the rsh-client package is not installed unless explicitly required.To remove the package, run: sudo apt-get remove rsh-client -y

