# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 263_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `263_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1538-1578 of the vulnerable file.

            switch(rsvp_obj_ctype) {
            case RSVP_CTYPE_TUNNEL_IPV4:
                while(obj_tlen >= 8) {
                    ND_PRINT((ndo, "%s  PLR-ID: %s, Avoid-Node-ID: %s",
                           ident,
                           ipaddr_string(ndo, obj_tptr),
                           ipaddr_string(ndo, obj_tptr + 4)));
                    obj_tlen-=8;
                    obj_tptr+=8;
                }
                break;
            default:
                hexdump=TRUE;
            }
            break;

        case RSVP_OBJ_CLASSTYPE:
        case RSVP_OBJ_CLASSTYPE_OLD: /* fall through */
            switch(rsvp_obj_ctype) {
            case RSVP_CTYPE_1:
                ND_PRINT((ndo, "%s  CT: %u",
                       ident,
                       EXTRACT_32BITS(obj_tptr) & 0x7));
                obj_tlen-=4;
                obj_tptr+=4;
                break;
            default:
                hexdump=TRUE;
            }
            break;

        case RSVP_OBJ_ERROR_SPEC:
            switch(rsvp_obj_ctype) {
            case RSVP_CTYPE_3: /* fall through - FIXME add TLV parser */
            case RSVP_CTYPE_IPV4:
                if (obj_tlen < 8)
                    return-1;
                error_code=*(obj_tptr+5);
                error_value=EXTRACT_16BITS(obj_tptr+6);
                ND_PRINT((ndo, "%s  Error Node Address: %s, Flags: [0x%02x]%s  Error Code: %s (%u)",
                       ident,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1555,6 +1555,7 @@
         case RSVP_OBJ_CLASSTYPE_OLD: /* fall through */
             switch(rsvp_obj_ctype) {
             case RSVP_CTYPE_1:
+                ND_TCHECK_32BITS(obj_tptr);
                 ND_PRINT((ndo, "%s  CT: %u",
                        ident,
                        EXTRACT_32BITS(obj_tptr) & 0x7));
```
