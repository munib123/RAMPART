# HackerOne Report: page_controls_menu_js can reveal collection version of page
**Report ID:** 4938
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
By visiting the url /tools/required/page_controls_menu_js?cID=<cID>&cvID=<cvID>

Where cID = page cID and cvID is unknown,

If for cvID you start at 1 (and the currently approved version is not the first version) the code `$(function() { ccmAlert.hud('This page is pending approval.', 5000); });` is added to the header.

If they increment the cvID to what the current approved version of a page, that line of code will go away. This discloses the currently approved version of a page (cvID of it).

This disclosure could be used with another attack to do harm to a site.

## Discussion & Remediation Timeline
