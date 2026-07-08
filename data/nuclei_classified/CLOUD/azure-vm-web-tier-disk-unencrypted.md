# Vulnerability: Azure VM Web-Tier Disk Volumes Not Encrypted
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-vm-web-tier-disk-unencrypted.yaml`)

## Description
Ensure that all the disk volumes attached to the Microsoft Azure virtual machines (VMs) launched within the web tier are encrypted to meet security and compliance requirements. This rule assumes all Azure cloud resources in the web tier are tagged with <web_tier_tag>:<web_tier_tag_value>. Tags must be configured on the Cloud Conformity dashboard prior to running this check.

## Secure Mitigation
Enable encryption for all disk volumes attached to VMs within the Azure web tier to enhance data security and comply with regulatory requirements.

