# Nuclei Template: Electron Applications - Cross-Site Scripting & Remote Code Execution
**Template ID:** node-integration-enabled
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Critical
**Source:** Nuclei Template (`node-integration-enabled.yaml`)

## Vulnerability Information & PoC

## Description
Electron Applications is susceptible to remote code execution by way of cross-site scripting via nodeIntegration  by calling require('child_process').exec('COMMAND');.

## References
- https://blog.yeswehack.com/yeswerhackers/exploitation/pentesting-electron-applications/
- https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-web/electron-desktop-apps/index.html#rce-xss--nodeintegration
