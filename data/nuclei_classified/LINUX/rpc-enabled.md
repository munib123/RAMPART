# Vulnerability: Unnecessary RPC Service (rstatd) Enabled
**Classification:** LINUX
**Source:** Nuclei Template (`rpc-enabled.yaml`)

## Description
Unnecessary RPC services like rstatd were enabled, allowing attackers to exploit buffer overflow, DoS, or remote execution vulnerabilities to gain root privileges and compromise the system.These services were expected to be disabled unless explicitly required.

