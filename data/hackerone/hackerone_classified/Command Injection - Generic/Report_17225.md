# HackerOne Report: SQL injection, tile ID
**Report ID:** 17225
**Vulnerability Class:** Command Injection - Generic

## Vulnerability Information & PoC
The tile ID parameter to the tile image script is vulnerable to SQL injection.

The following will cause the script to run a benchmark, returning 8-10 seconds later:

https://staging.uzbey.com/tiles1600/693/sleep(10)

## Discussion & Remediation Timeline
