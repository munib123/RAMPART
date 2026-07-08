# Vulnerability: GKE Node Pools Without Secure Boot Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-gke-secure-boot-disabled.yaml`)

## Description
Ensure that the Secure Boot security feature is enabled for your GKE cluster nodes to protect them against malware and rootkits. Secure Boot helps ensure that the system runs only authentic software by verifying the digital signature of all boot components, and halts the boot process if signature verification fails.

## Secure Mitigation
Re-create your node pools with Secure Boot enabled using:
gcloud container node-pools create POOL_NAME --cluster=CLUSTER_NAME --shielded-secure-boot

