# Vulnerability: Containers run with allowPrivilegeEscalation enabled
**Classification:** CLOUD
**Source:** Nuclei Template (`k8s-allow-privilege-escalation-set.yaml`)

## Description
Checks for containers running with the allowPrivilegeEscalation flag enabled, which can increase security risks by allowing privileges to be escalated

## Secure Mitigation
Ensure that the allowPrivilegeEscalation flag is set to false in all container configurations to minimize security risks

