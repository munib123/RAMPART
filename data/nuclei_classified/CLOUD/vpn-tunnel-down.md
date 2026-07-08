# Vulnerability: AWS VPN Tunnel Down
**Classification:** CLOUD
**Source:** Nuclei Template (`vpn-tunnel-down.yaml`)

## Description
Ensures AWS VPN tunnels are in an UP state, facilitating uninterrupted network traffic through the Virtual Private Network.

## Secure Mitigation
Monitor VPN tunnel status via the AWS Management Console or CLI. If a tunnel is DOWN, troubleshoot according to AWS documentation and ensure redundancy by configuring multiple tunnels.

