# HackerOne Report: XML Parser Bug: XXE over which leads to RCE
**Report ID:** 55431
**Vulnerability Class:** Code Injection

## Vulnerability Information & PoC
Hello security team,

I have reported this issue on Feb 6, 2015 and i'm resubmit it here again.
I was able to do XXE attack on your site and exposed the /etc/passwd file.
Scenario:
1. Login to drchrono  site.
2. Click on patients->patient
3. Click on ' Update patient (via C-CDA XML).'
4. Select the file I attached, (AXAX000001.xml), I download it from your site and added there struct for my exploit.
5. Click on 'Preview' and you'll see the content of /etc/passwd, (That can be any file on the system or any command). See xxe.png atttachement.


Best regards,
Sasi

## Discussion & Remediation Timeline
