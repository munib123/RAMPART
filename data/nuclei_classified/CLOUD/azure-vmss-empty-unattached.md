# Vulnerability: Azure Virtual Machine Scale Sets Empty and Unattached
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-vmss-empty-unattached.yaml`)

## Description
Identify any empty virtual machine scale sets available within your Microsoft Azure cloud account and delete them in order to eliminate unnecessary costs and meet compliance requirements when it comes to unused resources. A Microsoft Azure virtual machine scale set is considered empty when it doesn't have any VM instances attached anymore and is no longer associated with a load balancer.

## Secure Mitigation
Regularly check and remove any VM scale sets that do not contain any VM instances and are not associated with any load balancers.

