# Vulnerability: Ensure Talk Client is Not Installed
**Classification:** CIS
**Source:** Nuclei Template (`talk-client.yaml`)

## Description
The talk package provides a client for user-to-user messaging on local or remote systems.Since it uses unencrypted communication, it should be removed to minimize security risks.

## Secure Mitigation
Ensure the talk package is not installed unless explicitly required.To remove the package, run: sudo apt-get remove talk -y

