# Vulnerability: Azure VMSS Load Balancer Unassociated
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-vmss-load-balancer-unassociated.yaml`)

## Description
Ensure that each Microsoft Azure virtual machine scale set is integrated with a load balancer in order to distribute incoming traffic among healthy virtual machine instances running within the scale set. Azure load balancer is a layer 4 load balancer that provides low latency, high throughput, and scales up to millions of flows for all TCP and UDP web applications.

## Secure Mitigation
Ensure each Azure virtual machine scale set is integrated with a load balancer to distribute incoming traffic effectively among instances.

