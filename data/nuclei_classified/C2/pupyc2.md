# Vulnerability: PupyC2 - Detect
**Classification:** C2
**Source:** Nuclei Template (`pupyc2.yaml`)

## Description
Pupy is a cross-platform, multi function RAT and post-exploitation tool mainly written in python. It features an all-in-memory execution guideline and leaves a very low footprint. Pupy can communicate using multiple transports, migrate into processes using reflective injection, and load remote python code, python packages and python C-extensions from memory.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
```

