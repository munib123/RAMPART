# HackerOne Report: SSL Not Enforced
**Report ID:** 1425
**Vulnerability Class:** Uncategorized

## Vulnerability Information & PoC
Although by default, all the communication in the Secret web app happens over HTTPS, if this is changed to HTTP, the requests are still normally processed. 

For example, the request to send a download link to a phone number can be as simple as
POST /_/send-download-link HTTP/1.1
Host: www.secret.ly

{"PhoneNumber":"xxxxxxxxxx"}

The above request is sent to the target www.secret.ly over HTTP. This is successfully processed and the phone number in question gets a link to download the application.

Not to mention, an attacker can automate this and spam users sending them links to download this app even if they are not interested. There is also no controlling factor to stop the spam. This might be considered a totally different issue but I am reporting it together with this. 

## Discussion & Remediation Timeline
