# Vulnerability: VM Instance Confidential Computing Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-vm-confidential-computing-disabled.yaml`)

## Description
Ensure that the Confidential Computing security feature is enabled for your Google Cloud virtual machine (VM) instances in order to add protection to your sensitive data in use by keeping it encrypted in memory and using encryption keys that Google doesn't have access to. Confidential Computing is a breakthrough technology which encrypts data while it is being processed. This technology keeps data encrypted in memory, outside the CPU.

## Secure Mitigation
Re-create your VM instances with Confidential Computing enabled. Note that enabling this feature requires compatible machine types (N2D series) and may change certain instance parameters if they were set to incompatible values.

