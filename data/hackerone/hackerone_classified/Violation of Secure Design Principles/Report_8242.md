# HackerOne Report: Allowed method disclosure
**Report ID:** 8242
**Vulnerability Class:** Violation of Secure Design Principles

## Vulnerability Information & PoC
The URL "https://respond.ly/" has the following allowed methods, which include DAV methods: ACL, BASELINE_CONTROL, CHECKIN, CHECKOUT, CONNECT, COPY, DEBUG, GET, HEAD, INDEX, INVALID, INVOKE, LABEL, LINK, LOCK, MERGE, MKACTIVITY, MKCOL, MKDIR, MKWORKSPACE, MOVE, NOTIFY, OPTIONS, PATCH, PIN, POLL, POST, PROPFIND, PROPPATCH, REPLY, REPORT, RMDIR, SEARCH, SHOWMETHOD, SPACEJUMP, SUBSCRIBE, SUBSCRIPTIONS, TEXTSEARCH, TRACK, UNCHECKOUT, UNLINK, UNLOCK, UNSUBSCRIBE, VERSION_CONTROL.

Might wanna remove this

## Discussion & Remediation Timeline
