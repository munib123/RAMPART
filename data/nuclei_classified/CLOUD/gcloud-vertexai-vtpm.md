# Vulnerability: Virtual Trusted Platform Module Not Enabled for Vertex AI Notebooks
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-vertexai-vtpm.yaml`)

## Description
Ensure that the Virtual Trusted Platform Module (vTPM) feature is enabled for your Vertex AI notebook instances in order to protect them against persistent and advanced attacks. vTPM safeguards the guest VM's boot process by validating its integrity before and during startup. Additionally, it provides secure generation and protection for encryption keys.

## Secure Mitigation
Enable vTPM for Vertex AI notebook instances using the 'gcloud workbench instances update' command with --shielded-vtpm flag set to true. Note that instances must be stopped before updating this configuration.

