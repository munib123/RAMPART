# Vulnerability: Customer-Managed Key Not Tagged in Azure App Tier
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-app-tier-cmk-untagged.yaml`)

## Description
Ensure that a Customer-Managed Key (CMK), also known as Bring Your Own Key (BYOK), is created and configured for your Microsoft Azure application tier to meet cloud security and compliance requirements. The conformity rule assumes all Azure cloud resources in your app tier are tagged with <app_tier_tag>:<app_tier_tag_value>. The tag set for your Azure application tier must be pre-configured in the Cloud Conformity console.

## Secure Mitigation
Ensure all Customer-Managed Keys used in the application tier are properly tagged according to organizational policies. Update the key's metadata through the Azure portal or Azure CLI.

