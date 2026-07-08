# Vulnerability: Persistent Disks Attached to Suspended Virtual Machines
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-persistent-disks-suspended-vms.yaml`)

## Description
Ensure that persistent disks are not attached to suspended virtual machine (VM) instances in your Google Cloud environment. Persistent disks attached to suspended VMs continue to incur charges even when the VM is not running, leading to unnecessary costs.

## Secure Mitigation
Identify and detach persistent disks from suspended VMs, or delete the disks if they are no longer needed to optimize cloud resource costs.

