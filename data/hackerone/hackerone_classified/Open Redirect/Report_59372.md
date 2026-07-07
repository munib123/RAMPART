# HackerOne Report: Homograph Attack
**Report ID:** 59372
**Vulnerability Class:** Open Redirect

## Vulnerability Information & PoC
Hello HackerOne,

Fix of Report #29491 and #58612 is incomplete.
I found another way to to replicate homograph attack using Hex Code:

_www.%00ebаy.com_
_www.%01ebаy.com_
_www.%02ebаy.com_
_www.%03ebаy.com_
_www.%04ebаy.com_
_www.%05ebаy.com_
_www.%06ebаy.com_
_www.%07ebаy.com_
_www.%08ebаy.com_
_www.%0Bebаy.com_
_www.%0Cebаy.com_
_www.%0Eebаy.com_
_www.%0Febаy.com_
_www.%10ebаy.com_
_www.%1Aebаy.com_
_www.%1Bebаy.com_
_www.%1Cebаy.com_
_www.%1Debаy.com_
_www.%1Eebаy.com_
_www.%1Febаy.com_

Internationalized Domain Name or IDN are displayed in **Unicode** and there is no *encoding* into **Punycode** on external link warning page

Thanks,
@atom

## Discussion & Remediation Timeline
