# Vulnerability: DNSSEC Signing for Route 53 Hosted Zones - Disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`route53-dnssec-signing-disabled.yaml`)

## Description
Ensure that Domain Name System Security Extensions (DNSSEC) signing is enabled for your Amazon Route 53 public hosted zones in order to protect your domains against spoofing and cache poisoning attacks. By default, DNSSEC signing is not enabled for Route 53 hosted zones.

## Secure Mitigation
Enable DNSSEC signing in the Route 53 console for the hosted zone, sign the zone with a strong key algorithm, and ensure all DNS records are published correctly.

