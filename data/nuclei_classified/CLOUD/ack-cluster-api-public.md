# Vulnerability: Public Access to ACK Cluster's API Server - Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`ack-cluster-api-public.yaml`)

## Description
Ensure that your ACK cluster's API server is not publicly accessible in order to avoid exposing private data and minimizing security risks. The level of access to your Kubernetes API server depends on your application use cases, however, for most use cases, the Kubernetes API Server should be accessible only from within your Virtual Private Cloud (VPC).

