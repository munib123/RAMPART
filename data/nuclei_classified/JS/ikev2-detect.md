# Vulnerability: IKEv2 Service - Detection
**Classification:** JS
**Source:** Nuclei Template (`ikev2-detect.yaml`)

## Description
Detects IKEv2 services by sending a crafted IKE_SA_INIT request over UDP/500 and analyzing the response. Supports multiple cipher suites and DH groups for broad compatibility; any valid IKEv2 reply confirms the service.

