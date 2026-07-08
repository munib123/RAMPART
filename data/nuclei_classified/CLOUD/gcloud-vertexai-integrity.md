# Vulnerability: Integrity Monitoring Not Enabled for Vertex AI Notebooks
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-vertexai-integrity.yaml`)

## Description
Ensure that the Integrity Monitoring feature is enabled for your Google Cloud Vertex AI notebook instances to automatically check and monitor the runtime boot integrity of your shielded notebook instances using Google Cloud Monitoring. The feature requires Virtual Trusted Platform Module (vTPM) and helps ensure that the boot loader on your instances remains untampered.

## Secure Mitigation
Enable integrity monitoring for Vertex AI notebook instances using the 'gcloud workbench instances update' command with --shielded-integrity-monitoring flag set to true. Note that instances must be stopped before updating this configuration.

