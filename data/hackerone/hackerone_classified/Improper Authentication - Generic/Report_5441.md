# HackerOne Report: Hack administrator password even if you are a guest
**Report ID:** 5441
**Vulnerability Class:** Improper Authentication - Generic

## Vulnerability Information & PoC
Step1:Go to command prompt
Step2:Type "net user"
Step3:Find the administrator name which you would like to change the password
Step4:Type " net user" space "administrator name" space  *
Step5:It will ask you to change the password
Step6:Type the password and confirm it..

## Discussion & Remediation Timeline
