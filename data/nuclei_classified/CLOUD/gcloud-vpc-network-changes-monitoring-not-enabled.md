# Vulnerability: Enable VPC Network Changes Monitoring
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-vpc-network-changes-monitoring-not-enabled.yaml`)

## Description
Ensure that each Google Cloud Platform (GCP) project has configured an alerting policy that is triggered each time a Virtual Private Cloud (VPC) network change is made. The log filter pattern used to recognize VPC network changes is "resource.type=gce_network AND protoPayload.methodName=beta.compute.networks.insert OR protoPayload.methodName=beta.compute.networks.patch OR protoPayload.methodName=v1.compute.networks.delete OR protoPayload.methodName=v1.compute.networks.removePeering OR protoPayload.methodName=v1.compute.networks.addPeering".

## Secure Mitigation
Configure a logs-based metric with the specified filter pattern and create an alerting policy to monitor Virtual Private Cloud (VPC) network changes for all GCP projects.

