# Vulnerability: TrackmaniaLadder User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`trackmanialadder.yaml`)

## Description
TrackmaniaLadder user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://en.tm-ladder.com/{{user}}_rech.php
```

