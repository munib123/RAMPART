# HackerOne Report: Reflected XSS on vimeo.com/musicstore
**Report ID:** 85615
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
__Description__

The value of the parameter _section_ is reflected in the Javascript function `MusicStoreCommon.initialize()` without escaping, which allows to insert Javascript code.

__Proof of concept__
1. Go to https://vimeo.com/musicstore?section=%27-alert(document.domain)-%27.
2. `alert(document.domain)` is executed.

This reflected XSS is reproducible on Chrome, Safari and Firefox.

## Discussion & Remediation Timeline
