# HackerOne Report: HTML/XSS rendered in Android App of Crashlytics through fabric.io
**Report ID:** 41856
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
Hey hi,

While in fabric , the app name is rendered as HTML/XSS in android app of Crashlytics  like shown in the screenshot.

Steps to reproduce:
Create an app with the name of payload in my case i have used, "><img src=x>
under the following URL https://www.fabric.io/img-srcx-onerrorprompt03/android/apps/imgsrcxonerrorprompt0.myapplication/beta/releases/latest
(replace the app names wherever needed)
Send invitation to users to test the APP
users will get the invitation and will be forced to download the Crashlytics app,
once downloaded they will see the app name like in the screenshot.


Regards,
Karthik
Wesecureapp

## Discussion & Remediation Timeline
