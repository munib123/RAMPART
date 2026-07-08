# Vulnerability: Block Project-Wide SSH Keys Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-vm-project-ssh-keys-enabled.yaml`)

## Description
Ensure that your Google Compute Engine instances are configured to ignore GCP project-wide (shared) public SSH keys and use instance-level SSH keys instead. Project-wide SSH keys can be used to log in to all the VM instances running inside a GCP project. While project-wide SSH keys can ease SSH key management, if compromised, they pose a security risk which can impact all VM instances within the project.

## Secure Mitigation
Enable "Block Project-Wide SSH Keys" feature for your VM instances and configure instance-specific SSH keys instead. This limits the impact if any single key is compromised.

