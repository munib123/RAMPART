# Vulnerability: Ensure autofs Service is Not Installed
**Classification:** CIS
**Source:** Nuclei Template (`autofs-service.yaml`)

## Description
The autofs package provides the automounting service, which mounts file systems automatically on demand. If not explicitly required, having this service installed increases the system’s attack surface and should be avoided.

## Secure Mitigation
- Ensure the `autofs` package is not installed unless explicitly required.
- To disable the service if present, run: sudo systemctl disable --now autofs 2>/dev/null || true
- To remove the package, run: sudo apt-get purge -y autofs
- To clean up dependencies, run: sudo apt-get autoremove -y
- To verify removal, run: dpkg-query -s autofs || echo "autofs not installed"

