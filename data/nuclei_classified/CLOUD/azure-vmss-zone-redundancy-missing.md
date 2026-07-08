# Vulnerability: Azure VMSS Zone-Redundant Configuration Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-vmss-zone-redundancy-missing.yaml`)

## Description
Ensure that all your Microsoft Azure virtual machine scale sets are using zone-redundant availability configurations instead of single-zone (zonal) configurations, to deploy and load balance virtual machines (VMs) across multiple Availability Zones (AZs) in order to protect the scale sets from datacenter-level failures.

## Secure Mitigation
Configure your VMSS to use zone-redundant availability configurations to ensure high availability and fault tolerance across multiple data centers.

