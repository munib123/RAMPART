# Vulnerability: Azure Storage Default Network Access Not Restricted
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-storage-network-unrestricted.yaml`)

## Description
Ensure that your Microsoft Azure Storage account is configured to deny access to traffic from all networks (including Internet traffic). By restricting access to your storage account default network, you add a new layer of security, since the default action is to accept connections from clients on any network. To limit access to selected networks or IP addresses, you must first change the default action from "Allow" to "Deny".

## Secure Mitigation
Configure the network access rule for Azure Storage accounts to "Deny" to restrict access to selected networks only, enhancing security by preventing unwanted or unauthorized access.

