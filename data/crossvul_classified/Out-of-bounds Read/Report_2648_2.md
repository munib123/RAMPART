# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2648_2
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2648_2`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 87-127 of the vulnerable file.

    { 3, "Reply via an IPv4/IPv6 UDP packet with Router Alert"},
    { 4, "Reply via application level control channel"},
    { 0, NULL}
};

static const struct tok lspping_return_code_values[] = {
    {  0, "No return code or return code contained in the Error Code TLV"},
    {  1, "Malformed echo request received"},
    {  2, "One or more of the TLVs was not understood"},
    {  3, "Replying router is an egress for the FEC at stack depth"},
    {  4, "Replying router has no mapping for the FEC at stack depth"},
    {  5, "Reserved"},
    {  6, "Reserved"},
    {  7, "Reserved"},
    {  8, "Label switched at stack-depth"},
    {  9, "Label switched but no MPLS forwarding at stack-depth"},
    { 10, "Mapping for this FEC is not the given label at stack depth"},
    { 11, "No label entry at stack-depth"},
    { 12, "Protocol not associated with interface at FEC stack depth"},
    { 13, "Premature termination of ping due to label stack shrinking to a single label"},
};


/*
 * LSPPING TLV header
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |             Type              |            Length             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             Value                             |
 * .                                                               .
 * .                                                               .
 * .                                                               .
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

struct lspping_tlv_header {
    uint8_t type[2];
    uint8_t length[2];
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -104,6 +104,7 @@
     { 11, "No label entry at stack-depth"},
     { 12, "Protocol not associated with interface at FEC stack depth"},
     { 13, "Premature termination of ping due to label stack shrinking to a single label"},
+    { 0,  NULL},
 };
 
 
```
