# Vulnerability: VM Instance Preemptibility Not Disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-vm-preemptible-enabled.yaml`)

## Description
Ensure that your Google Cloud Platform (GCP) projects are not using preemptible virtual machine instances for production and business-critical applications. A preemptible virtual machine (VM) is an instance that you can create and run at a much lower price than normal instances but it can be terminated sooner due to system demands.

## Secure Mitigation
Re-create your VM instances with preemptibility disabled. Note that you cannot disable preemptibility on an existing instance - you must create a new instance without the preemptible option.

