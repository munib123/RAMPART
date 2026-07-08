# Vulnerability: RDS Instance Storage AutoScaling - Disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`rds-instance-autoscaling-disabled.yaml`)

## Description
Ensure that the Storage AutoScaling feature is enabled for your Amazon RDS database instances in order to provide dynamic scaling support for the database's storage based on your RDS application needs.

## Secure Mitigation
Enable storage autoscaling for the RDS instance in the AWS Management Console or via CLI/API to automatically adjust storage capacity as needed.

