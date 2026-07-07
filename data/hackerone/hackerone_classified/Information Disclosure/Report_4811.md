# HackerOne Report: dashboard/pages/types [Unknown column 'Array' in 'where clause'] disclosure.
**Report ID:** 4811
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
Hi,

When I go to /index.php/dashboard/pages/types?ctID[]=4&task=edit I get thrown the following :
`mysqlt error: [1054: Unknown column 'Array' in 'where clause'] in EXECUTE("SELECT PageTypes.ctID, ComposerTypes.ctID as ctIDc, ctHandle, ctIsInternal, ctName, ctIcon, pkgID, ctComposerPublishPageMethod, ctComposerPublishPageTypeID, ctComposerPublishPageParentID from PageTypes left join ComposerTypes on PageTypes.ctID = ComposerTypes.ctID where PageTypes.ctID = Array")`

It's not a SQL Injection but it also shouldn't happen..

Best regards,

Olivier Beg

## Discussion & Remediation Timeline
