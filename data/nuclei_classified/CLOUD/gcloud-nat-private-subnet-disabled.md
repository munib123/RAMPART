# Vulnerability: Cloud NAT Not Enabled for Private Subnets
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-nat-private-subnet-disabled.yaml`)

## Description
Ensure that Cloud NAT is enabled for all private VPC subnets that require outbound access. Cloud NAT enables your VMs and container pods to establish outbound connections to the Internet or other Virtual Private Cloud (VPC) networks. It utilizes a Cloud NAT gateway to manage these connections efficiently.

## Secure Mitigation
Configure Cloud NAT for all private subnets that require outbound access. Use Compute Engine routers to define NAT configuration and associate them with your VPC subnets.

