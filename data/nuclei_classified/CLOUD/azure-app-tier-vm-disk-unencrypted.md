# Vulnerability: Azure App-Tier VM Disk Encryption Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-app-tier-vm-disk-unencrypted.yaml`)

## Description
Ensure that all the disk volumes attached to the Microsoft Azure virtual machines (VMs) provisioned within the application tier are encrypted to meet security and compliance requirements. The Azure cloud resources in the app tier should be tagged with `<app_tier_tag>:<app_tier_tag_value>`.

## Secure Mitigation
Enable disk encryption on all Azure virtual machine disk volumes within the application tier by using Azure Disk Encryption.

