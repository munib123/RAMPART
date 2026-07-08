# Vulnerability: Azure VM Premium SSD Not Required
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-vm-standard-ssd-required.yaml`)

## Description
Ensure that your Microsoft Azure virtual machines (VMs) are using Standard SSD disk volumes instead of Premium SSD volumes for cost-effective storage that fits a broad range of workloads from web servers to enterprise applications that need consistent performance at lower IOPS levels. Unless you are running mission-critical applications or performance sensitive workloads that need more than 6000 IOPS or 750 MiB/s of throughput per VM disk volume, Cloud Conformity recommends converting your Premium SSD volumes to Standard SSD in order to lower the cost of your Azure monthly bill.

## Secure Mitigation
Convert any Premium SSD volumes to Standard SSD unless the workload requires high performance disk specifications. This can be achieved through Azure's portal or via CLI commands.

