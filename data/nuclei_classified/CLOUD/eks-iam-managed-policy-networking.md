# Vulnerability: Use AWS-managed policy to Manage Networking Resources
**Classification:** CLOUD
**Source:** Nuclei Template (`eks-iam-managed-policy-networking.yaml`)

## Description
Ensure that all Amazon EKS cluster node groups use the "AmazonEKS_CNI_Policy" managed policy to manage cloud networking resources effectively. This policy provides the necessary permissions to the Amazon VPC CNI Plugin for managing network interfaces.

## Secure Mitigation
Attach the AmazonEKS_CNI_Policy to the IAM role associated with your EKS node groups using either the AWS Console or AWS CLI.

