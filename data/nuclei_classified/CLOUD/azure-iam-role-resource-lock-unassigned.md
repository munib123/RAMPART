# Vulnerability: Azure IAM Role for Resource Locking Not Assigned
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-iam-role-resource-lock-unassigned.yaml`)

## Description
Ensure there is a custom IAM role assigned to manage resource locking within each Microsoft Azure subscription. Azure resource locking is a powerful protection mechanism that can prevent inadvertent modification or deletion of resources. This role should have specific permissions to read, write, and delete resource locks.

## Secure Mitigation
Create a custom IAM role with permissions for Microsoft.Authorization/locks/read, Microsoft.Authorization/locks/write, and Microsoft.Authorization/locks/delete and ensure it is assigned to an identity.

