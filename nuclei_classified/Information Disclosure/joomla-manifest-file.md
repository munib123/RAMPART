# Nuclei Template: Joomla! Manifest File - Disclosure
**Template ID:** joomla-manifest-file
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`joomla-manifest-file.yaml`)

## Vulnerability Information & PoC

## Description
A Joomla! Manifest file was discovered. joomla.xml is a file which stores information about installed Joomla!, such as version, files, and paths.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/administrator/manifests/files/joomla.xml
```

