# HackerOne Report: Ability to add pishing links in discusion ," Bypassing uneductional Links  add "
**Report ID:** 62301
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
{refer to case number 247874}

Hey devs ,

IF you went in course discussion and tried to add for example " evil.com " it will get blocked by your system . But if you tried to add

https://support.udemy.com/ it will be added directly


So using a thing i learned in old times th ' @ ' sign after a website url like this site.com@anothersite.com it will actually redirect to to anothersite.com It is because modern browsers interpret this scheme like this "http://authorization_data@website", so, when You click on URL, they get You redirected to "http://website". so this was the way i bypassed the system adding any pishing link in the end of support.udemy.com link or any whitelisted site :


Example :

https://support.udemy.com@evil.com/


add it in a discussion and a successfull bypass is done and it will be added to discussion flawlessly .


Now ability to pish user into telling them check this support and they will be confident it's a udemy link but you will dircect them to scam site . 


Here is live example :


https://www.udemy.com/course/244336/activities?ids=1415990


So this is it you need not to allow any link with @ in it : Also if you say that the variant after @ will appear as misleading it can be URL encoded ! 

Thanks !

## Discussion & Remediation Timeline
