# Vulnerability: Cakefile - Exposure
**Classification:** CWE-538
**Source:** Nuclei Template (`cakefile-exposure.yaml`)

## Description
Detected CoffeeScript Cakefile was exposing build tasks and project structure.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/Cakefile
GET {{BaseURL}}/src/Cakefile
GET {{BaseURL}}/app/Cakefile
GET {{BaseURL}}/lib/Cakefile
GET {{BaseURL}}/build/Cakefile
GET {{BaseURL}}/node_modules/whet.extend/Cakefile
GET {{BaseURL}}/node_modules/Cakefile
```

