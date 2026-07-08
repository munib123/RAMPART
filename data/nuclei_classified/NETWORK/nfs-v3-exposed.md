# Vulnerability: NFSv3 Exposed
**Classification:** NETWORK
**Source:** Nuclei Template (`nfs-v3-exposed.yaml`)

## Description
This version of the protocol did not implement native encryption and transmitted all data in clear text over the network. Also, this version of NFSv3 relied on client IP address and UID/GID matching for authentication,mechanisms that were easily bypassed by attackers with control over their client machines.

