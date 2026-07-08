# Vulnerability: Automatic Upgrades Not Enabled for Vertex AI Notebooks
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-vertexai-auto-upgrades.yaml`)

## Description
Ensure that automatic upgrades for Vertex AI Workbench notebook instances are enabled to get the latest features, performance improvements, and security updates without manual intervention. Once auto-upgrades are enabled, Vertex AI Workbench will check, during a recurring time period that you specify, whether your notebook instances can be upgraded, and if so, the service will upgrade your instances.

## Secure Mitigation
Enable automatic upgrades for Vertex AI notebook instances using the 'gcloud workbench instances update' command with metadata parameter 'notebook-upgrade-schedule'. Example: --metadata 'notebook-upgrade-schedule=3 12 * * SUN' for weekly Sunday upgrades.

