# Vulnerability: Secure Boot Not Enabled for Vertex AI Notebooks
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-vertexai-secure-boot.yaml`)

## Description
Ensure that the Secure Boot security feature is enabled for your Vertex AI notebook instances in order to protect them against malware and rootkits. Secure Boot helps ensure that the system runs only authentic software by verifying the digital signature of all boot components, and halts the boot process if the signature verification fails. Secure Boot is disabled by default because of the third-party unsigned kernel modules that can't be loaded when the feature is enabled.

## Secure Mitigation
Enable Secure Boot for Vertex AI notebook instances using the 'gcloud workbench instances update' command with --shielded-secure-boot flag set to true. Note that instances must be stopped before updating this configuration.

