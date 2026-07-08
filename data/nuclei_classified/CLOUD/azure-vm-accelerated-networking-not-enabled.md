# Vulnerability: Azure VM Accelerated Networking Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-vm-accelerated-networking-not-enabled.yaml`)

## Description
Ensure that Accelerated Networking feature is enabled for your Azure virtual machines (VMs) in order to provide low latency and high throughput for the network interfaces (NICs) attached to the VMs. Accelerated networking enables single root input/output virtualization (SR-IOV) for virtual machines, vastly improving its networking performance. This high-performance pathway bypasses the host from the datapath, reducing latency, jitter, and CPU utilization, so it can be used with the most demanding network workloads that can be installed on the supported VM types.

## Secure Mitigation
Enable Accelerated Networking on all Azure VMs that support this feature to ensure optimal networking performance.

