# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 262_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `262_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 382-422 of the vulnerable file.

	if ((subobj_len % 4) != 0) {
	    ND_PRINT((ndo, " (not a multiple of 4)"));
	    break;
	}
	if (total_subobj_len < subobj_len) {
	    ND_PRINT((ndo, " (goes past the end of the object)"));
	    break;
	}
	switch(subobj_type) {
	case INT_SWITCHING_TYPE_SUBOBJ:
	    ND_PRINT((ndo, "\n\t      Switching Type: %s (%u)",
		tok2str(gmpls_switch_cap_values,
			"Unknown",
			EXTRACT_8BITS(obj_tptr + offset + 2)),
			EXTRACT_8BITS(obj_tptr + offset + 2)));
	    ND_PRINT((ndo, "\n\t      Encoding Type: %s (%u)",
		tok2str(gmpls_encoding_values,
			"Unknown",
			EXTRACT_8BITS(obj_tptr + offset + 3)),
			EXTRACT_8BITS(obj_tptr + offset + 3)));
	    bw.i = EXTRACT_32BITS(obj_tptr+offset+4);
	    ND_PRINT((ndo, "\n\t      Min Reservable Bandwidth: %.3f Mbps",
                bw.f*8/1000000));
	    bw.i = EXTRACT_32BITS(obj_tptr+offset+8);
	    ND_PRINT((ndo, "\n\t      Max Reservable Bandwidth: %.3f Mbps",
                bw.f*8/1000000));
	    break;
	case WAVELENGTH_SUBOBJ:
	    ND_PRINT((ndo, "\n\t      Wavelength: %u",
		EXTRACT_32BITS(obj_tptr+offset+4)));
	    break;
	default:
	    /* Any Unknown Subobject ==> Exit loop */
	    hexdump=TRUE;
	    break;
	}
	total_subobj_len-=subobj_len;
	offset+=subobj_len;
    }
    return (hexdump);
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -399,6 +399,7 @@
 			"Unknown",
 			EXTRACT_8BITS(obj_tptr + offset + 3)),
 			EXTRACT_8BITS(obj_tptr + offset + 3)));
+	    ND_TCHECK_32BITS(obj_tptr + offset + 4);
 	    bw.i = EXTRACT_32BITS(obj_tptr+offset+4);
 	    ND_PRINT((ndo, "\n\t      Min Reservable Bandwidth: %.3f Mbps",
                 bw.f*8/1000000));
@@ -419,6 +420,8 @@
 	offset+=subobj_len;
     }
     return (hexdump);
+trunc:
+    return -1;
 }
 
 void
@@ -429,7 +432,7 @@
     const struct lmp_object_header *lmp_obj_header;
     const u_char *tptr,*obj_tptr;
     u_int tlen,lmp_obj_len,lmp_obj_ctype,obj_tlen;
-    int hexdump;
+    int hexdump, ret;
     u_int offset;
     u_int link_type;
 
@@ -731,7 +734,10 @@
                        ipaddr_string(ndo, obj_tptr+8),
                        EXTRACT_32BITS(obj_tptr+8)));
 
-		if (lmp_print_data_link_subobjs(ndo, obj_tptr, obj_tlen - 12, 12))
+		ret = lmp_print_data_link_subobjs(ndo, obj_tptr, obj_tlen - 12, 12);
+		if (ret == -1)
+		    goto trunc;
+		if (ret == TRUE)
 		    hexdump=TRUE;
 		break;
 
@@ -751,7 +757,10 @@
                        ip6addr_string(ndo, obj_tptr+20),
                        EXTRACT_32BITS(obj_tptr+20)));
 
-		if (lmp_print_data_link_subobjs(ndo, obj_tptr, obj_tlen - 36, 36))
+		ret = lmp_print_data_link_subobjs(ndo, obj_tptr, obj_tlen - 36, 36);
+		if (ret == -1)
+		    goto trunc;
+		if (ret == TRUE)
 		    hexdump=TRUE;
 		break;
 
@@ -771,7 +780,10 @@
                        EXTRACT_32BITS(obj_tptr+8),
                        EXTRACT_32BITS(obj_tptr+8)));
 
-		if (lmp_print_data_link_subobjs(ndo, obj_tptr, obj_tlen - 12, 12))
+		ret = lmp_print_data_link_subobjs(ndo, obj_tptr, obj_tlen - 12, 12);
+		if (ret == -1)
+		    goto trunc;
+		if (ret == TRUE)
 		    hexdump=TRUE;
 		break;
 
```
