# HackerOne Report: LZ4 Core
**Report ID:** 17688
**Vulnerability Class:** Memory Corruption - Generic

## Vulnerability Information & PoC
#############################################################################
#
# Lab Mouse Security Report 
# LMS-2014-06-16-6
#

Report ID: LMS-2014-06-16-6
CVE ID: CVE-2014-4611

Researcher Name: Don A. Bailey
Researcher Organization: Lab Mouse Security
Researcher Email: donb at securitymouse.com
Researcher Website: www.securitymouse.com

Vulnerability Status: Reported / No response
Vulnerability Embargo: Broken

Vulnerability Class: Integer Overflow
Vulnerability Effect: Memory Corruption
Vulnerability Impact: DoS, OOW, RCE
Vulnerability DoS Practicality: Practical
Vulnerability OOW Practicality: Practical
Vulnerability RCE Practicality: Untested
Vulnerability Criticality: High

Vulnerability Scope:
All versions of the LZ4 software:
https://code.google.com/p/lz4

Functions Affected:
	lz4.c:LZ4_decompress_generic

Criticality Reasoning
---------------------
Due to the design of the algorithm, an attacker can specify any desired
offset to a write pointer. The attacker can instrument the write in such
a way as to only write four bytes at a specified offset. Subsequent code
will allow the attacker to escape from the decompression algorithm without
further memory corruption. This may allow the attacker to overwrite 
critical structures in memory that affect flow of execution. White DoS
and OOW are obvious side effects of this flaw, RCE with respect to this
flaw is untested. 

Vulnerability Description
-------------------------
An integer overflow can occur when processing any variant of a "literal run"
in the affected function. 

Vulnerability Resolution
------------------------
Pending.


## Discussion & Remediation Timeline
