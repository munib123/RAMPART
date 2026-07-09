# Nuclei Template: Infoblox NetMRI < 7.6.1 - Remote Code Execution via Hardcoded Ruby Cookie Secret Key
**Template ID:** infoblox-netmri-rails-cookie-rce
**Vulnerability Class:** Deserialization of Untrusted Data
**Severity:** Critical
**CWE:** CWE-502
**Source:** Nuclei Template (`infoblox-netmri-rails-cookie-rce.yaml`)

## Vulnerability Information & PoC

## Description
Infoblox NetMRI virtual appliances before version 7.6.1 are vulnerable to remote code execution (RCE) due to the use of a hardcoded Ruby on Rails session cookie secret key. The Rails web component deserializes session cookies if the signing key is valid. Attackers with knowledge of this key can craft malicious session cookies that are deserialized by the application, leading to arbitrary code execution. This vulnerability is related to the known Ruby on Rails deserialization flaw (CVE-2013-0156). Infoblox did not assign a new CVE for this issue, as it is a result of the underlying Rails vulnerability.

## Impact
An attacker can exploit this vulnerability to execute arbitrary commands on the NetMRI server, potentially leading to complete system compromise.

## Steps to reproduce / Exploit Payload
```http
GET /webui/gui_states/index.json HTTP/1.1
Host: {{Hostname}}
Cookie: _netmri={{urlencode(marshal_data)}}--{{signature}}
```

## Remediation
Upgrade Infoblox NetMRI to version 7.6.1 or later to mitigate this vulnerability.

## References
- https://rhinosecuritylabs.com/research/infoblox-multiple-cves/
- https://nvd.nist.gov/vuln/detail/CVE-2013-0156
