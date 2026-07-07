# HackerOne Report: homograph attack. IDNs displayed in unicode in bug reports and on external link warning page
**Report ID:** 29491
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
the IDN: http://ebаy.com/

is a homograph for the latin ebay.com. if you click that first link, youm might think that you are going to ebay.com. in fact, you are going to a homograph url http://xn--eby-7cd.com/

more info http://www.chromium.org/developers/design-documents/idn-in-google-chrome

more info http://www.charset.org/punycode.php?encoded=http%3A%2F%2Fxn--eby-7cd.com%2F&decode=Punycode+to+normal+text

it would be safer to show the punycode version of the url so that it would be apparent that something weird is going on. that is, show http://xn--eby-7cd.com/ instead of http://ebаy.com/

## Discussion & Remediation Timeline
