# Vulnerability: VM Instance Using Public IP Address
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-vm-public-ip-enabled.yaml`)

## Description
Ensure that your Google Compute Engine instances are not configured to have external IP addresses in order to minimize their exposure to the Internet. To reduce attack surface, Google Cloud virtual machine (VM) instances should not have public IP addresses attached. Instead, VM instances should be configured to run behind load balancers.

## Secure Mitigation
Remove external IP addresses from your VM instances using the 'gcloud compute instances delete-access-config' command or through the Google Cloud Console. Configure instances to run behind load balancers instead.

