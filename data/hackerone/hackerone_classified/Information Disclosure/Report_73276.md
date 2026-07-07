# HackerOne Report: Internet-based attacker can run Flash apps in local sandboxes by using  special URL schemes (PSIRT-3299, CVE-2015-3079)
**Report ID:** 73276
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
Some of the sandbox logic of Flash Player can be circumvented on most web browsers by using special URL schemes. A website can deploy an SWF file via the data: or blob: URL schemes (perhaps others). An app started in this way runs in the "local with files" or "local with networking" sandbox, depending on the SWF attributes. This bug can be used in conjunction other attacks such as the Firefox-specific bug reported separately or MITM (CVE-2015-3044) to promote the local sandbox to "local trusted". This would allow unlimited cross-domain access.

On Chrome, the SWF can simply be encoded in a data: URL. This doesn't appear to work on other browsers (maybe there is a limit on the URL length or something else). On Firefox, Safari (recent versions, not version 5), and Chrome also allow loading the SWF from a blob: URL. On Firefox this apparently requires prefixing the URL with "feed:".

The vulnerability was patched in May 2015.


## Discussion & Remediation Timeline
