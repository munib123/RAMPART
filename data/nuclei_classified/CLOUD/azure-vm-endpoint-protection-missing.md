# Vulnerability: Azure VM Endpoint Protection Not Installed
**Classification:** CLOUD
**Source:** Nuclei Template (`azure-vm-endpoint-protection-missing.yaml`)

## Description
Ensure that all your Microsoft Azure virtual machines (VMs) have endpoint protection installed in order to help you identify and remove viruses, spyware, and other malicious software. The Azure Security Center service monitors the status of anti-malware protection for Azure virtual machines (VMs) and highlights if there is insufficient protection, marking the virtual machines without endpoint protection as vulnerable to malware threats.

## Secure Mitigation
Install an approved endpoint protection solution on your Azure VMs to mitigate the risk of malware and maintain compliance with organizational security policies.

