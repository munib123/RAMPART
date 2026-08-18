# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2724_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2724_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1455-1495 of the vulnerable file.

                    return-1;
                ND_PRINT((ndo, "%s  IPv4 Tunnel Sender Address: %s, LSP ID: 0x%04x"
                       "%s  Sub-Group Originator ID: %s, Sub-Group ID: 0x%04x",
                       ident,
                       ipaddr_string(ndo, obj_tptr),
                       EXTRACT_16BITS(obj_tptr+6),
                       ident,
                       ipaddr_string(ndo, obj_tptr+8),
                       EXTRACT_16BITS(obj_tptr + 12)));
                obj_tlen-=16;
                obj_tptr+=16;
                break;
            default:
                hexdump=TRUE;
            }
            break;

        case RSVP_OBJ_FASTREROUTE:
            /* the differences between c-type 1 and 7 are minor */
            obj_ptr.rsvp_obj_frr = (const struct rsvp_obj_frr_t *)obj_tptr;
            bw.i = EXTRACT_32BITS(obj_ptr.rsvp_obj_frr->bandwidth);

            switch(rsvp_obj_ctype) {
            case RSVP_CTYPE_1: /* new style */
                if (obj_tlen < sizeof(struct rsvp_obj_frr_t))
                    return-1;
                ND_PRINT((ndo, "%s  Setup Priority: %u, Holding Priority: %u, Hop-limit: %u, Bandwidth: %.10g Mbps",
                       ident,
                       (int)obj_ptr.rsvp_obj_frr->setup_prio,
                       (int)obj_ptr.rsvp_obj_frr->hold_prio,
                       (int)obj_ptr.rsvp_obj_frr->hop_limit,
                        bw.f * 8 / 1000000));
                ND_PRINT((ndo, "%s  Include-any: 0x%08x, Exclude-any: 0x%08x, Include-all: 0x%08x",
                       ident,
                       EXTRACT_32BITS(obj_ptr.rsvp_obj_frr->include_any),
                       EXTRACT_32BITS(obj_ptr.rsvp_obj_frr->exclude_any),
                       EXTRACT_32BITS(obj_ptr.rsvp_obj_frr->include_all)));
                obj_tlen-=sizeof(struct rsvp_obj_frr_t);
                obj_tptr+=sizeof(struct rsvp_obj_frr_t);
                break;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1472,12 +1472,12 @@
         case RSVP_OBJ_FASTREROUTE:
             /* the differences between c-type 1 and 7 are minor */
             obj_ptr.rsvp_obj_frr = (const struct rsvp_obj_frr_t *)obj_tptr;
-            bw.i = EXTRACT_32BITS(obj_ptr.rsvp_obj_frr->bandwidth);
 
             switch(rsvp_obj_ctype) {
             case RSVP_CTYPE_1: /* new style */
                 if (obj_tlen < sizeof(struct rsvp_obj_frr_t))
                     return-1;
+                bw.i = EXTRACT_32BITS(obj_ptr.rsvp_obj_frr->bandwidth);
                 ND_PRINT((ndo, "%s  Setup Priority: %u, Holding Priority: %u, Hop-limit: %u, Bandwidth: %.10g Mbps",
                        ident,
                        (int)obj_ptr.rsvp_obj_frr->setup_prio,
@@ -1496,6 +1496,7 @@
             case RSVP_CTYPE_TUNNEL_IPV4: /* old style */
                 if (obj_tlen < 16)
                     return-1;
+                bw.i = EXTRACT_32BITS(obj_ptr.rsvp_obj_frr->bandwidth);
                 ND_PRINT((ndo, "%s  Setup Priority: %u, Holding Priority: %u, Hop-limit: %u, Bandwidth: %.10g Mbps",
                        ident,
                        (int)obj_ptr.rsvp_obj_frr->setup_prio,
```
