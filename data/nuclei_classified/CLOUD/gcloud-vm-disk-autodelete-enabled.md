# Vulnerability: Auto-Delete Not Disabled for VM Instance Persistent Disks
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-vm-disk-autodelete-enabled.yaml`)

## Description
Ensure that the Auto-Delete behavior rule is disabled for the persistent disks attached to your Google Cloud virtual machine (VM) instances in order to protect the VM data from being deleted and meet security and compliance requirements. When Auto-Delete is on, the persistent disks are deleted when the associated VM instance is deleted.

## Secure Mitigation
Disable Auto-Delete for your VM instance persistent disks using the 'gcloud compute instances set-disk-auto-delete' command or through the Google Cloud Console. This ensures disks are retained after instance deletion.

