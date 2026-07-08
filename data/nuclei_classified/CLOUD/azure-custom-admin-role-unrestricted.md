# Vulnerability: Azure Subscription Administrator Custom Role Unrestricted Access
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-custom-admin-role-unrestricted.yaml`)

## Description
To provide optimal access security and adhere to the Principle of Least Privilege (POLP), ensure there are no custom administrator roles created for your Microsoft Azure cloud subscriptions. POLP involves assigning only the necessary privileges instead of granting full administrative access.

## Secure Mitigation
Review and restrict the permissions of custom roles in Azure cloud subscriptions. Ensure that custom roles do not grant more privileges than necessary by conforming to the Principle of Least Privilege.

