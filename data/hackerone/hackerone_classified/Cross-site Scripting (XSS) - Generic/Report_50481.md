# HackerOne Report: Self Xss on File Replace
**Report ID:** 50481
**Vulnerability Class:** Cross-site Scripting (XSS) - Generic

## Vulnerability Information & PoC
In File manager there is an Replace option to replace files from three resources .
1. from computer
2.incoming
3.Remote files
For remote files if we put 
http://example.com/"><img src=x onerror=confirm('name')>

in the url box
It reflects xss.
Poc: https://www.dropbox.com/s/m7pb9wiwxix1oyu/replacexss.mkv?dl=0

Thanks

## Discussion & Remediation Timeline
