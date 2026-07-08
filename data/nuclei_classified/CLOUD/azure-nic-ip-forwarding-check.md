# Vulnerability: Review Network Interfaces with IP Forwarding Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-nic-ip-forwarding-check.yaml`)

## Description
Ensure that all Microsoft Azure network interfaces (NICs) with IP forwarding enabled are regularly reviewed for security and compliance reasons. IP forwarding allows a virtual machine (VM) to receive and send network traffic not intended for its own IP, used primarily by network virtual appliances.

## Secure Mitigation
Regularly review and validate the necessity of IP forwarding settings on Azure NICs. Ensure that only authorized and secure virtual appliances use this feature.

