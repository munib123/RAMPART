# Vulnerability: Infoblox NetMRI < 7.6.1 - Remote Code Execution via Hardcoded Ruby Cookie Secret Key
**Classification:** CWE-502
**Source:** Nuclei Template (`infoblox-netmri-rails-cookie-rce.yaml`)

## Description
Infoblox NetMRI virtual appliances before version 7.6.1 are vulnerable to remote code execution (RCE) due to the use of a hardcoded Ruby on Rails session cookie secret key. The Rails web component deserializes session cookies if the signing key is valid. Attackers with knowledge of this key can craft malicious session cookies that are deserialized by the application, leading to arbitrary code execution. This vulnerability is related to the known Ruby on Rails deserialization flaw (CVE-2013-0156). Infoblox did not assign a new CVE for this issue, as it is a result of the underlying Rails vulnerability.

## Secure Mitigation
Upgrade Infoblox NetMRI to version 7.6.1 or later to mitigate this vulnerability.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /webui/gui_states/index.json HTTP/1.1
Host: {{Hostname}}
Cookie: _netmri={{urlencode(marshal_data)}}--{{signature}}
```

