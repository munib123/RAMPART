# HackerOne Report: Cheating at gallery rating
**Report ID:** 76784
**Vulnerability Class:** Privilege Escalation

## Vulnerability Information & PoC
Hello!

Example: http://www.zaption.com/listing/55aba5719c77e5386eb28df0

We can rate tour any mark by POST http://www.zaption.com/ajax/gallery/listing/{tour_id}/rate/{mark}
For example:
POST http://www.zaption.com/ajax/gallery/listing/55aba5719c77e5386eb28df0/rate/100000000000000000

So, we have "curve" layout and cheating in voting.

Thank you for reading this report!

## Discussion & Remediation Timeline
