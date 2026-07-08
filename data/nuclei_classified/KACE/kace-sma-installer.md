# Vulnerability: KACE Systems Management Appliance - Installer
**Classification:** KACE
**Source:** Nuclei Template (`kace-sma-installer.yaml`)

## Description
The exposure of the KACE Systems Management Appliance’s installer interface through the /common/setup.php endpoint allowed unauthorized access to the system setup wizard. This interface was publicly accessible when it should have been restricted, potentially granting attackers the ability to initiate or manipulate the setup process, leading to system compromise or unauthorized configuration changes.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/common/setup.php
```

