# HackerOne Report: Markdown code block sequence makes report unreadable
**Report ID:** 46952
**Vulnerability Class:** Uncategorized

## Vulnerability Information & PoC
**Proof of Concept**

Submitting a report/comment with an input like the following

"Three backticks followed by a newline followed by `-d*{d}d/<<d`"

will cause the report to be unreadable (I think it's because the parser is crashing?)

The attached file includes the input that I'm trying (with difficulty) to describe with text, since I can't actually include the crasher in the report.

This may have no security implications; the worst I can imagine doing with this is annoying people by creating reports that can't easily be closed.


## Discussion & Remediation Timeline
