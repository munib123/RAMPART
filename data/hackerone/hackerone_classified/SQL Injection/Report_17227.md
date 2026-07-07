# HackerOne Report: SQL injection, time zoom script, tile ID
**Report ID:** 17227
**Vulnerability Class:** SQL Injection

## Vulnerability Information & PoC
The tile ID parameter to the tile zoom script is vulnerable to SQL injection.

The following will cause the script to run a benchmark, returning an error 8-10 seconds later:

https://staging.uzbey.com/zoom-image/BENCHMARK(10000000,SHA1(1))

## Discussion & Remediation Timeline
