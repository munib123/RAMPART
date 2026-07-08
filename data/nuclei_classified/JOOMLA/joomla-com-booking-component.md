# Vulnerability: Joomla! com_booking component 2.4.9 - Information Leak
**Classification:** JOOMLA
**Source:** Nuclei Template (`joomla-com-booking-component.yaml`)

## Description
Joomla! com_booking component suffers from Information leak vulnerability in which sensitive or confidential data is unintentionally exposed or made accessible to unauthorized individuals or systems.

## Vulnerable Code Pattern / Exploit Payload
```http
GET /index.php?option=com_booking&controller=customer&task=getUserData&id=123 HTTP/1.1
```

