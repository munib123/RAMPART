# Vulnerability: EKS Kubernetes Secrets not Encrypted
**Classification:** CLOUD
**Source:** Nuclei Template (`eks-kubernetes-secrets-encryption.yaml`)

## Description
Ensure that your Amazon Elastic Kubernetes Service (EKS) clusters have encryption enabled for Kubernetes secrets using AWS KMS Customer Master Keys (CMKs). This is a security best practice for protecting sensitive data stored in Kubernetes secrets.

## Secure Mitigation
Enable encryption for your EKS cluster by creating a KMS CMK and configuring it for the cluster. Note that this requires recreating the cluster with the encryption configuration.

