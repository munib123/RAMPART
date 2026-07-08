# Vulnerability: IKEv2 Deep Vendor ID Version - Detection
**Classification:** JS
**Source:** Nuclei Template (`ikev2-vid-version.yaml`)

## Description
Detected valid IKEv1 VPN group names by sending Aggressive Mode probes with different IDi values. Extracts vendor, version, and capability details from IKEv2 Vendor ID and Notify payloads using a single unauthenticated exchange.

