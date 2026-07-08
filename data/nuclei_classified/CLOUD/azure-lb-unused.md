# Vulnerability: Azure Unused Load Balancer Check
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-lb-unused.yaml`)

## Description
Identify any unused load balancers available within your Azure cloud account and delete them in order to eliminate unnecessary costs and meet compliance requirements when it comes to cloud resource management. A Microsoft Azure load balancer is considered unused when it doesn't have any associated backend pool instances. The backend pool instances can be individual virtual machines or instances running within a virtual machine scale set.

## Secure Mitigation
Review and remove unused load balancers that do not have any backend pool instances.

