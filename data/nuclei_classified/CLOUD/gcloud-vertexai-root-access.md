# Vulnerability: Root Access Not Disabled for Vertex AI Notebooks
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-vertexai-root-access.yaml`)

## Description
Ensure that root access to your Google Cloud Vertex AI notebook instances is disabled in order to reduce the risk of accidental or malicious system damage by limiting administrative privileges within the instances. Disabling root access minimizes the risk of unauthorized modifications and helps maintain a more controlled and secure AI environment.

## Secure Mitigation
Disable root access for Vertex AI notebook instances using the 'gcloud workbench instances update' command with metadata parameter 'notebook-disable-root=true'. Note that instances must be stopped before updating this configuration.

