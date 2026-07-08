# Vulnerability: Azure VM Performance Diagnostics Feature Not Enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-vm-performance-diagnostics-unenabled.yaml`)

## Description
Ensure that Performance Diagnostics feature is enabled for your Microsoft Azure virtual machine instances to help mitigate VM performance issues. Performance Diagnostics installs a VM extension that runs PerfInsights, available for both Windows and Linux operating systems. PerfInsights collects and analyzes diagnostic information to provide findings and recommendations for performance issues.

## Secure Mitigation
Enable the Performance Diagnostics feature by installing the AzurePerformanceDiagnostics extension through Azure Portal or Azure CLI commands to mitigate performance issues and ensure optimal VM operation.

