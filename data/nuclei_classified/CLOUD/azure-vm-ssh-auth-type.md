# Vulnerability: Azure VM SSH Authentication Type Not Using Keys
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-vm-ssh-auth-type.yaml`)

## Description
Ensure that your production Microsoft Azure virtual machines are configured to use SSH keys instead of username/password credentials for SSH authentication. Using SSH keys enhances security by eliminating the risks associated with password-based authentication.

## Secure Mitigation
Configure all Azure virtual machines to use SSH keys for authentication. Disable password authentication to enhance the security of your virtual machines.

