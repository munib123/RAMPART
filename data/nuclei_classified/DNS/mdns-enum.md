# Vulnerability: mDNS Enumeration
**Classification:** DNS
**Source:** Nuclei Template (`mdns-enum.yaml`)

## Description
mDNS may disclose details about services running on a local network. When mDNS traffic is accessible from the public Internet, attackers can exploit it to map internal services. If exposure is suspected, perform enumeration with tools such as dig to collect additional information.

