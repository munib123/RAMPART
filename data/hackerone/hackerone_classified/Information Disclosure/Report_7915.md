# HackerOne Report: Uninitialized variable error message leaks information 
**Report ID:** 7915
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
An uninitialized variable `$alert` at line 630 in `index.php` shows an error message. This happens after a `POST /pages/create_project`. The error message does not appear in the browser because the user is redirected to the new project immediately, but it is there in the HTTP response (see error.png).

This is probably fixed with something like this at line 630.
`if(isset($alert)) echo UI::getPage(UI::PAGE_CREATE_PROJECT, array($alert));`

## Discussion & Remediation Timeline
