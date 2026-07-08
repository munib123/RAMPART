# Vulnerability: VM IP Forwarding Not Restricted
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-org-ip-forwarding.yaml`)

## Description
Ensure that the virtual machine (VM) instances allowed to use IP forwarding, that belong to your project, folder, or organization, are defined using the "Restrict VM IP Forwarding" policy. This constraint policy helps you improve security and achieve regulatory compliance by explicitly defining the resource name of the VM instances allowed to use IP forwarding.

## Secure Mitigation
Configure the "Restrict VM IP Forwarding" policy at the organization level to explicitly specify which VM instances can use IP forwarding. Use the format projects/<project-id>/zones/<instance-zone>/instances/<instance-name> or under: prefix for broader scopes.

