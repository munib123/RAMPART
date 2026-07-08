# Vulnerability: Cloud Monitor for ACK Clusters - Disable
**Classification:** CLOUD
**Source:** Nuclei Template (`ack-cluster-cloud-monitor-disable.yaml`)

## Description
Ensure that Cloud Monitor is enabled for your Container Service for Kubernetes (ACK) clusters. Cloud Monitor relies on a specialized agent for accessing extra system resources and application services within virtual machine instances. The agent allows monitoring of metrics such as CPU utilization, specific disk traffic metrics, network traffic, and disk IO information. These metrics play a crucial role in observing signals and facilitating operational activities within your Kubernetes Engine clusters.

