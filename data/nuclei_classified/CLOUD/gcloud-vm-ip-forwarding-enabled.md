# Vulnerability: IP Forwarding Not Disabled for VM Instances
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-vm-ip-forwarding-enabled.yaml`)

## Description
Ensure that IP Forwarding feature is not enabled at the Google Compute Engine instance level for security and compliance reasons, as instances with IP Forwarding enabled act as routers/packet forwarders. Because IP forwarding is rarely required, except when the virtual machine (VM) is used as a network virtual appliance, each Google Cloud VM instance should be reviewed to decide whether IP forwarding is really needed.

## Secure Mitigation
Re-create your VM instances with IP forwarding disabled. Note that you cannot disable IP forwarding on an existing instance - you must create a new instance without the IP forwarding option.

