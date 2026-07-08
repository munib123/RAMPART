# Vulnerability: RPC Portmapper (UDP) - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`rpc-udp-detect.yaml`)

## Description
Detects Sun RPC Portmapper (rpcbind) service on UDP port 111 using amap and Nmap RPC probes for reliable identification. An exposed Portmapper may reveal RPC services like NFS or NIS and enable further enumeration or attacks.

