# HackerOne Report: Cross-Site Scripting in getMarketplacePurchaseFrame
**Report ID:** 6843
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
The `$mp->getProductBlockID()` variable in the `getMarketplacePurchaseFrame` function ([view on Github](https://github.com/concrete5/concrete5/blob/851806af393fa2958d52db9b48e0a8c83100f609/web/concrete/core/libraries/marketplace.php#L176)) is not being filtered properly to protect against HTML injection/XSS.

This leads to XSS vulnerabilities in (for example) `connect.php` on line 14 ([view on Github](https://github.com/concrete5/concrete5/blob/851806af393fa2958d52db9b48e0a8c83100f609/web/concrete/single_pages/dashboard/extend/connect.php#L14)) when visiting a URL like: *dashboard/extend/connect/"%20onmouseover="alert(document.cookie)">*.

## Discussion & Remediation Timeline
