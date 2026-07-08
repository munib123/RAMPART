# Vulnerability: Kubernetes Cluster Logging
**Classification:** CLOUD
**Source:** Nuclei Template (`eks-cluster-logging.yaml`)

## Description
Ensure that your Amazon Elastic Kubernetes Service (EKS) clusters have control plane logs enabled to publish API, audit, controller manager, scheduler and authenticator logs to AWS CloudWatch Logs.

## Secure Mitigation
Enable control plane logging for your EKS cluster by configuring all log types (api, audit, authenticator, controllerManager, scheduler) in the cluster configuration.

