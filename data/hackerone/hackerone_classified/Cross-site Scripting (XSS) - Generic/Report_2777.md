# HackerOne Report: Reflected Xss
**Report ID:** 2777
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
1. go to https://auth.slack.com/generate/
2. input username and password, and submit the request. 
3. In the next step application asks for the password you just created like the application says "We're almost done. Just need to test that you remember your password. Enter it again for me". Enter the password again(you created in previous step), submit and intercept the request using burp intruder.
4. Modify the 'u' param to a xss payload like u=<img src=x onerror=alert(1)>
5. Submit the request and check the response, the application does not properly escape the special char and hence xss got executed.

For better reproduction use Firefox

## Discussion & Remediation Timeline
