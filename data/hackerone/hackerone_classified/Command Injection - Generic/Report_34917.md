# HackerOne Report: Bypassed or command injection
**Report ID:** 34917
**Vulnerability Class:** Command Injection - Generic

## Vulnerability Information & PoC
Respected sir,

Step1:sign up an account
Step2:set secret pin
Step3:After that a tick box is asking " I will lose my coins if I forget my Secret PIN and Secret Mnemonic. I know this."..
Step4:If you check the tick box , the button "done" will enable.It is mandatory to check the box.

The bug is,

I bypassed this tick box feature.Without checking the tick box i applied command injection to the done button.
I changed the disabled to enabled in the coding part of the done button.Then i clicked done button without accepting the tickbox.

Please check the video for details..

## Discussion & Remediation Timeline
