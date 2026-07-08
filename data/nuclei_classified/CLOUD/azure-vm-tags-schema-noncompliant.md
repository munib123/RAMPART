# Vulnerability: Azure VM Tags Schema Non-compliant
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-vm-tags-schema-noncompliant.yaml`)

## Description
Ensure that user-defined tags are being used for labeling, collecting, and organizing cloud resources within your Microsoft Azure account. User-defined tags are name/value pairs that enable you to categorize resources and view consolidated billing by applying the same tag to multiple cloud resources. Trend Micro Cloud One™ – Conformity recommends the following tagging schema to help you identify and manage your Azure resources: Name, Role, Environment, and Owner.

## Secure Mitigation
Update the tagging schema of your Azure virtual machines to include the recommended tags: Name, Role, Environment, and Owner to ensure effective resource management and billing.

