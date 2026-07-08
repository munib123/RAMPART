# Vulnerability: Electron Applications - Cross-Site Scripting & Remote Code Execution
**Classification:** ELECTRON
**Source:** Nuclei Template (`node-integration-enabled.yaml`)

## Description
Electron Applications is susceptible to remote code execution by way of cross-site scripting via nodeIntegration  by calling require('child_process').exec('COMMAND');.

