# Vulnerability: Cloud Monitoring Not Enabled for Vertex AI Notebooks
**Classification:** CLOUD
**Source:** Nuclei Template (`gcloud-vertexai-monitoring.yaml`)

## Description
Ensure that Cloud Monitoring is enabled for your Vertex AI notebook instances in order to gain visibility into their health and performance. Cloud Monitoring reports system and application metrics such as disk, CPU, network, and processes. This allows you to identify issues like resource bottlenecks or errors proactively. To enable the monitoring feature, you must install the Cloud Monitoring agent when you create your notebook instance.

## Secure Mitigation
Re-create Vertex AI notebook instances with Cloud Monitoring enabled by using the 'gcloud workbench instances create' command with metadata parameter 'install-monitoring-agent=true'.

