# Vulnerability: Use AWS-managed policy to manage AWS resources
**Classification:** CLOUD
**Source:** Nuclei Template (`eks-aws-managed-iam-policy.yaml`)

## Description
Ensure that all Amazon EKS clusters use the "AmazonEKSClusterPolicy" managed policy to efficiently manage the resources that you use with the EKS service. This policy grants Kubernetes the necessary permissions to handle resources on your behalf.

## Secure Mitigation
Attach the AmazonEKSClusterPolicy to the IAM role associated with your EKS cluster using either the AWS Console or AWS CLI.

