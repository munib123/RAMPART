# Vulnerability: VM Instance Automatic Restart Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-vm-automatic-restart-disabled.yaml`)

## Description
Ensure that Google Cloud Compute Engine service restarts automatically your virtual machine instances when they are terminated due to non-user initiated reasons such as maintenance events, hardware, and software failures. The Automatic Restart feature configures the virtual machine restart behavior when an instance crashes or it is terminated by the system.

## Secure Mitigation
Enable automatic restart for your VM instances. Note that this behavior does not affect any terminations initiated by the user, such as when the instance is taken offline through a user action like calling sudo shutdown.

