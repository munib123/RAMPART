# Vulnerability: Azure Entra ID Guest Users Unmonitored
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-entra-id-guest-users-unmonitored.yaml`)

## Description
For a Microsoft Azure business-to-business (B2B) collaboration, each Microsoft Entra ID guest user needs to be associated with a business owner or business process. Ensure that there are no unassociated Microsoft Entra ID guest users within your Microsoft Azure account when there is no need for B2B collaboration.

## Secure Mitigation
Regularly review and monitor guest users in Microsoft Entra ID to ensure each is associated with a business owner or process. Remove any unnecessary guest user accounts.

