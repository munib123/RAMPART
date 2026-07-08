# Vulnerability: Use AWS-managed policy to access Amazon ECR Repositories
**Classification:** CLOUD
**Source:** Nuclei Template (`eks-managed-policy-ecr-access.yaml`)

## Description
Ensure that all EKS cluster node groups use the "AmazonEC2ContainerRegistryReadOnly" managed policy to access Amazon ECR repositories. This policy provides read-only access to Amazon EC2 Container Registry (ECR) repositories.

## Secure Mitigation
Attach the AmazonEC2ContainerRegistryReadOnly policy to the IAM role associated with your EKS node groups using either the AWS Console or AWS CLI.

