# Vulnerability: Root PATH Contains Current Directory
**Classification:** LOCAL
**Source:** Nuclei Template (`root-path-dot.yaml`)

## Description
root user’s PATH environment variable included the current directory (“.”).This allowed scripts or binaries in the working directory to be executed with root privileges. The misconfiguration resulted in potential privilege escalation and unsafe behavior.

