# Vulnerability: Dataproc Cluster Publicly Accessible
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-dataproc-public-access.yaml`)

## Description
Ensure that your Google Cloud Dataproc clusters are not configured with external IP addresses to minimize exposure to the Internet. When external IP addresses are assigned to Dataproc clusters, the cluster instances are exposed directly to the Internet. This increases the attack surface and risks accidental data exposure if firewall rules are misconfigured.

## Secure Mitigation
Re-create your Dataproc clusters with internal IP addresses only by using the '--no-address' flag or enabling 'Internal IP only' in the console. This ensures cluster instances use private IP addresses and communicate over internal networks only.

