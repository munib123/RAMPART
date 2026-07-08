# Vulnerability: EKS Cluster Endpoint Public Access
**Classification:** CLOUD
**Source:** Nuclei Template (`eks-endpoint-access.yaml`)

## Description
Ensure that your Amazon EKS cluster's Kubernetes API server endpoint is not publicly accessible from the Internet in order to avoid exposing private data and minimizing security risks.

## Secure Mitigation
Configure the EKS cluster endpoint access to be private or restrict public access to specific IP addresses. Use VPC endpoints and security groups to control access to the Kubernetes API server.

