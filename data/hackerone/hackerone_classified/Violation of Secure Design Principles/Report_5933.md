# HackerOne Report: Multiple Issues related to registering applications
**Report ID:** 5933
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
On the page https://coinbase.com/oauth/applications, an authenticated coinbase user can create an application and successfully submit it to the app gallery. 
 
After submitting, the app is pending review to be approved. However, while the app is in review, the coinbase user can send a URL (something like https://coinbase.com/apps/533fb2cb6e90eb79b9000103) to access the app to other users directly. In other words, the app is accessible to other users even without being reviewed by the coinbase team. The coinbase user might have malicious intentions and can trick other users to install the malicious app. 

Other users can also leave their reviews on this application. 

Lastly, after submitting an app for approval, there is an option to upload screenshots. There did not seem to be any restrictions on the kind of files that can be uploaded. I was able to upload an executable and I got a message saying it was successfully uploaded. I could not verify it because I believe it will only be visible once approved. 

## Discussion & Remediation Timeline
