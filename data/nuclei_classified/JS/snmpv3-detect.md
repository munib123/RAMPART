# Vulnerability: SNMPv3 Fingerprint - Detect
**Classification:** JS
**Source:** Nuclei Template (`snmpv3-detect.yaml`)

## Description
SNMPv3 can leak information about the device even without proper authentication.Use `nmap -sU <ADDRESS> -p 161 --script snmp-info` to get more information.Engine IDs can help to determine one device with multiple interfaces.

