# Vulnerability: Enable CloudTrail Logging for Kubernetes API Calls
**Classification:** CLOUD
**Source:** Nuclei Template (`eks-logging-kubes-api-calls.yaml`)

## Description
Ensure that CloudTrail logging is enabled for Amazon Elastic Kubernetes Service (EKS) clusters in order to record all Kubernetes API calls. Amazon CloudTrail records and documents all activities performed on EKS clusters.

## Secure Mitigation
Enable CloudTrail logging for your EKS clusters by either starting logging on existing trails or creating a new multi-region trail if none exists.

