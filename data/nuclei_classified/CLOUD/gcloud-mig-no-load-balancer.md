# Vulnerability: Managed Instance Group Not Using Load Balancer
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-mig-no-load-balancer.yaml`)

## Description
Ensure that each Managed Instance Group is using a load balancer to act as an instance group frontend. Google Cloud Managed Instance Groups (MIGs) are groups of virtual machine (VM) instances that you control as a single entity. MIGs support rich features such as autoscaling and autohealing, load balancing, multiple zone coverage, and stateful workloads.

## Secure Mitigation
Configure a load balancer for your Managed Instance Group by creating a backend service and associating it with your MIG. This ensures even traffic distribution and improved availability.

