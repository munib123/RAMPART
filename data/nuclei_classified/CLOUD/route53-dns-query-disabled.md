# Vulnerability: DNS Query Logging for Route 53 Hosted Zones - Disabled
**Classification:** CLOUD
**Source:** Nuclei Template (`route53-dns-query-disabled.yaml`)

## Description
Domain Name System Security Extensions (DNSSEC) represents a set of protocols that adds a layer of security to the Domain Name System (DNS) lookup and exchange processes by enabling DNS responses to be validated.

## Secure Mitigation
Enable DNS query logging in the Route 53 console for the hosted zone to capture and store DNS queries, allowing for better monitoring and analysis of DNS traffic.

