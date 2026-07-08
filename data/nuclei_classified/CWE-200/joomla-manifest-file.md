# Vulnerability: Joomla! Manifest File - Disclosure
**Classification:** CWE-200
**Source:** Nuclei Template (`joomla-manifest-file.yaml`)

## Description
A Joomla! Manifest file was discovered. joomla.xml is a file which stores information about installed Joomla!, such as version, files, and paths.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/administrator/manifests/files/joomla.xml
```

