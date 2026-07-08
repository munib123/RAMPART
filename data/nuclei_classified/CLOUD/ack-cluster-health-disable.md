# Vulnerability: ACK Clusters Check - Disable
**Classification:** CLOUD
**Source:** Nuclei Template (`ack-cluster-health-disable.yaml`)

## Description
Ensure that the Cluster Check feature is triggered at least once per week to guarantee proactive health monitoring for your ACK clusters, minimizing downtime and optimizing the reliability of your containerized applications. By default, Cluster Check is not automatically triggered, the cluster inspection can be started using the Container Service for Kubernetes (ACK) console.

