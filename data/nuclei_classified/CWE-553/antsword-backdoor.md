# Vulnerability: AntSword Backdoor Detection
**Classification:** CWE-553
**Source:** Nuclei Template (`antsword-backdoor.yaml`)

## Description
An AntSword application backdoor shell was discovered.

## Secure Mitigation
Reinstall AnstSword on a new system due to the target system's compromise. Follow best practices for securing PHP servers/applications via the php.ini and other mechanisms.

## Vulnerable Code Pattern / Exploit Payload
```http
POST {{BaseURL}}/.antproxy.php
```

