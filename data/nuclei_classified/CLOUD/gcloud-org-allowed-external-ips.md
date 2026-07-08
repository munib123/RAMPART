# Vulnerability: Organization Policy for Allowed External IPs Not Configured
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-org-allowed-external-ips.yaml`)

## Description
Ensure that "Define Allowed External IPs for VM Instances" constraint policy is enforced at the GCP organization level in order to enable you to define the set of virtual machine (VM) instances that are allowed to use external IP addresses. This constraint helps you to minimize your instance's exposure to the Internet.

## Secure Mitigation
Configure the "Define Allowed External IPs for VM Instances" policy at the organization level to explicitly specify which VM instances are allowed to have external IP addresses. Use the format: projects/<project-id>/zones/<instance-zone>/instances/<instance-name>.

