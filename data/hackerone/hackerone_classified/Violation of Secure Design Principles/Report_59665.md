# HackerOne Report: Local File Inclusion Vulnerability in Concrete5 version 5.7.3.1
**Report ID:** 59665
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
Concrete5 is vulnerable to a Local File Inclusion because it fails to properly validate the path for incoming requests during the dispatching process. This vulnerability exists because the path is retrieved using the Request::getPathInfo() method from the Symfony framework, which allows to specify the path for the request within some HTTP headers (like X-Original-URL and some others). However, this cannot be considered a vulnerability within the Symfony framework, but a vulnerability due to the way Concrete5 dispatches the request using that feature.

## Discussion & Remediation Timeline
