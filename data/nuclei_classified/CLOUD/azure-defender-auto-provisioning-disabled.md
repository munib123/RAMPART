# Vulnerability: Azure Defender for Cloud Automatic Provisioning Disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-defender-auto-provisioning-disabled.yaml`)

## Description
Ensure that the automatic provisioning extensions are enabled within the Microsoft Defender for Cloud settings to collect security data and events from your Azure virtual machines (VMs) and containers. By enabling Auto provisioning, you can ensure that the agents needed for processes such as vulnerability assessments, log analytics, and container monitoring are automatically installed on your infrastructure.

## Secure Mitigation
Enable the automatic provisioning feature within Microsoft Defender for Cloud to ensure that all necessary security agents are automatically deployed across your Azure resources.

