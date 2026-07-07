# HackerOne Report: Report title autocompletion
**Report ID:** 263
**Vulnerability Class:** Information Disclosure

## Vulnerability Information & PoC
Scenario:
1. Researcher uses a shared computer.
2. Researcher submits a report.
3. Researcher logs out.
4. Another person logs in, on another account.
5. Another person submits a report.
6. When entering a title, the title of the previous report submitted by the researcher is shown in autocompletion box.

This gives away the title of the bug to other users of the web browser, even though the researcher logged out properly.


## Discussion & Remediation Timeline
