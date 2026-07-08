# Vulnerability: Automountd Service Enabled
**Classification:** LOCAL
**Source:** Nuclei Template (`linux-automountd-enabled.yaml`)

## Description
The automountd service, when enabled or running, allowed a local attacker to execute arbitrary commands with root privileges by exploiting automatic mount options. This misconfiguration led to local privilege escalation.

