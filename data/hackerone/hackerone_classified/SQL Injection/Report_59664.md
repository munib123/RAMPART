# HackerOne Report: SQL Injection Vulnerability in Concrete5 version 5.7.3.1
**Report ID:** 59664
**Vulnerability Class:** SQL Injection

## Vulnerability Information & PoC
Concrete5 is vulnerable to a SQL Injection attack because certain user input is being used to construct a SQL query without proper validation. This vulnerability can be exploited only by authenticated users with privileges to edit page permissions.

## Discussion & Remediation Timeline
