# Vulnerability: Caucho Resin LFR
**Classification:** RESIN
**Source:** Nuclei Template (`resin-viewfile-lfr.yaml`)

## Description
There is an input verification vulnerability in the implementation of a certain CGI program in Resin. A remote attacker may use this vulnerability to read any files in the home directory of the Web, including JSP source code or class files.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/resin-doc/viewfile/?file=index.jsp
```

