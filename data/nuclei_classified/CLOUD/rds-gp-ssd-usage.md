# Vulnerability: RDS General Purpose SSD Usage
**Classification:** CLOUD
**Source:** Nuclei Template (`rds-gp-ssd-usage.yaml`)

## Description
Ensure Amazon RDS instances use General Purpose SSDs for cost-effective storage suitable for a wide range of workloads, except for applications needing over 10000 IOPS or 160 MiB/s throughput.

## Secure Mitigation
Convert RDS instances from Provisioned IOPS to General Purpose SSDs to optimize costs without sacrificing I/O performance for most database workloads.

