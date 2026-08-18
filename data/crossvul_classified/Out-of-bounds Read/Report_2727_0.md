# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2727_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2727_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1188-1228 of the vulnerable file.

                obj_tlen-=4+*(obj_tptr+3);
                obj_tptr+=4+*(obj_tptr+3);
                break;
            default:
                hexdump=TRUE;
            }
            break;

	case RSVP_OBJ_GENERALIZED_UNI:
            switch(rsvp_obj_ctype) {
		int subobj_type,af,subobj_len,total_subobj_len;

            case RSVP_CTYPE_1:

                if (obj_tlen < 4)
                    return-1;

		/* read variable length subobjects */
		total_subobj_len = obj_tlen;
                while(total_subobj_len > 0) {
                    subobj_len  = EXTRACT_16BITS(obj_tptr);
                    subobj_type = (EXTRACT_16BITS(obj_tptr+2))>>8;
                    af = (EXTRACT_16BITS(obj_tptr+2))&0x00FF;

                    ND_PRINT((ndo, "%s  Subobject Type: %s (%u), AF: %s (%u), length: %u",
                           ident,
                           tok2str(rsvp_obj_generalized_uni_values, "Unknown", subobj_type),
                           subobj_type,
                           tok2str(af_values, "Unknown", af), af,
                           subobj_len));

                    if(subobj_len == 0)
                        goto invalid;

                    switch(subobj_type) {
                    case RSVP_GEN_UNI_SUBOBJ_SOURCE_TNA_ADDRESS:
                    case RSVP_GEN_UNI_SUBOBJ_DESTINATION_TNA_ADDRESS:

                        switch(af) {
                        case AFNUM_INET:
                            if (subobj_len < 8)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1205,6 +1205,17 @@
 		/* read variable length subobjects */
 		total_subobj_len = obj_tlen;
                 while(total_subobj_len > 0) {
+                    /* If RFC 3476 Section 3.1 defined that a sub-object of the
+                     * GENERALIZED_UNI RSVP object must have the Length field as
+                     * a multiple of 4, instead of the check below it would be
+                     * better to test total_subobj_len only once before the loop.
+                     * So long as it does not define it and this while loop does
+                     * not implement such a requirement, let's accept that within
+                     * each iteration subobj_len may happen to be a multiple of 1
+                     * and test it and total_subobj_len respectively.
+                     */
+                    if (total_subobj_len < 4)
+                        goto invalid;
                     subobj_len  = EXTRACT_16BITS(obj_tptr);
                     subobj_type = (EXTRACT_16BITS(obj_tptr+2))>>8;
                     af = (EXTRACT_16BITS(obj_tptr+2))&0x00FF;
@@ -1216,7 +1227,13 @@
                            tok2str(af_values, "Unknown", af), af,
                            subobj_len));
 
-                    if(subobj_len == 0)
+                    /* In addition to what is explained above, the same spec does not
+                     * explicitly say that the same Length field includes the 4-octet
+                     * sub-object header, but as long as this while loop implements it
+                     * as it does include, let's keep the check below consistent with
+                     * the rest of the code.
+                     */
+                    if(subobj_len < 4 || subobj_len > total_subobj_len)
                         goto invalid;
 
                     switch(subobj_type) {
```
