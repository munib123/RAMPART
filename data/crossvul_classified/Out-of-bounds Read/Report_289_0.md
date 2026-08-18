# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 289_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `289_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 2334-2374 of the vulnerable file.

                cap_type=opt[i];
                cap_len=opt[i+1];
                tcap_len=cap_len;
                ND_PRINT((ndo, "\n\t      %s (%u), length: %u",
                       tok2str(bgp_capcode_values, "Unknown",
                                  cap_type),
                       cap_type,
                       cap_len));
                ND_TCHECK2(opt[i+2], cap_len);
                switch (cap_type) {
                case BGP_CAPCODE_MP:
                    ND_PRINT((ndo, "\n\t\tAFI %s (%u), SAFI %s (%u)",
                           tok2str(af_values, "Unknown",
                                      EXTRACT_16BITS(opt+i+2)),
                           EXTRACT_16BITS(opt+i+2),
                           tok2str(bgp_safi_values, "Unknown",
                                      opt[i+5]),
                           opt[i+5]));
                    break;
                case BGP_CAPCODE_RESTART:
                    ND_PRINT((ndo, "\n\t\tRestart Flags: [%s], Restart Time %us",
                           ((opt[i+2])&0x80) ? "R" : "none",
                           EXTRACT_16BITS(opt+i+2)&0xfff));
                    tcap_len-=2;
                    cap_offset=4;
                    while(tcap_len>=4) {
                        ND_PRINT((ndo, "\n\t\t  AFI %s (%u), SAFI %s (%u), Forwarding state preserved: %s",
                               tok2str(af_values,"Unknown",
                                          EXTRACT_16BITS(opt+i+cap_offset)),
                               EXTRACT_16BITS(opt+i+cap_offset),
                               tok2str(bgp_safi_values,"Unknown",
                                          opt[i+cap_offset+2]),
                               opt[i+cap_offset+2],
                               ((opt[i+cap_offset+3])&0x80) ? "yes" : "no" ));
                        tcap_len-=4;
                        cap_offset+=4;
                    }
                    break;
                case BGP_CAPCODE_RR:
                case BGP_CAPCODE_RR_CISCO:
                    break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2351,6 +2351,8 @@
                            opt[i+5]));
                     break;
                 case BGP_CAPCODE_RESTART:
+                    /* Restart Flags (4 bits), Restart Time in seconds (12 bits) */
+                    ND_TCHECK_16BITS(opt + i + 2);
                     ND_PRINT((ndo, "\n\t\tRestart Flags: [%s], Restart Time %us",
                            ((opt[i+2])&0x80) ? "R" : "none",
                            EXTRACT_16BITS(opt+i+2)&0xfff));
```
