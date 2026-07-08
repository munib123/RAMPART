# Vulnerability: IKEv2 Supported Transforms - Enumeration
**Classification:** JS
**Source:** Nuclei Template (`ikev2-transforms-enum.yaml`)

## Description
Enumerates supported IKEv2 encryption cipher suites by sending individual SA_INIT probes with single-algorithm proposals. Accepted ciphers return an SA payload response, while rejected ones return a NO_PROPOSAL_CHOSEN notification.

