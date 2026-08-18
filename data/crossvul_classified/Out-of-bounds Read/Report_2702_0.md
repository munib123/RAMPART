# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2702_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2702_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1386-1426 of the vulnerable file.


  ND_PRINT((ndo,  ", Digest: "));

  for(i=0;i<16;i++)
    ND_PRINT((ndo, "%.2x ", mcid->digest[i]));

trunc:
  ND_PRINT((ndo, "%s", tstr));
}

static int
isis_print_mt_port_cap_subtlv(netdissect_options *ndo,
                              const uint8_t *tptr, int len)
{
  int stlv_type, stlv_len;
  const struct isis_subtlv_spb_mcid *subtlv_spb_mcid;
  int i;

  while (len > 2)
  {
    stlv_type = *(tptr++);
    stlv_len  = *(tptr++);

    /* first lets see if we know the subTLVs name*/
    ND_PRINT((ndo, "\n\t       %s subTLV #%u, length: %u",
               tok2str(isis_mt_port_cap_subtlv_values, "unknown", stlv_type),
               stlv_type,
               stlv_len));

    /*len -= TLV_TYPE_LEN_OFFSET;*/
    len = len -2;

    switch (stlv_type)
    {
      case ISIS_SUBTLV_SPB_MCID:
      {
        ND_TCHECK2(*(tptr), ISIS_SUBTLV_SPB_MCID_MIN_LEN);

        subtlv_spb_mcid = (const struct isis_subtlv_spb_mcid *)tptr;

        ND_PRINT((ndo,  "\n\t         MCID: "));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1403,6 +1403,7 @@
 
   while (len > 2)
   {
+    ND_TCHECK2(*tptr, 2);
     stlv_type = *(tptr++);
     stlv_len  = *(tptr++);
 
@@ -1415,11 +1416,18 @@
     /*len -= TLV_TYPE_LEN_OFFSET;*/
     len = len -2;
 
+    /* Make sure the subTLV fits within the space left */
+    if (len < stlv_len)
+      goto trunc;
+    /* Make sure the entire subTLV is in the captured data */
+    ND_TCHECK2(*(tptr), stlv_len);
+
     switch (stlv_type)
     {
       case ISIS_SUBTLV_SPB_MCID:
       {
-        ND_TCHECK2(*(tptr), ISIS_SUBTLV_SPB_MCID_MIN_LEN);
+      	if (stlv_len < ISIS_SUBTLV_SPB_MCID_MIN_LEN)
+      	  goto trunc;
 
         subtlv_spb_mcid = (const struct isis_subtlv_spb_mcid *)tptr;
 
@@ -1434,15 +1442,17 @@
 
           /*tptr += SPB_MCID_MIN_LEN;
             len -= SPB_MCID_MIN_LEN; */
-        tptr = tptr + sizeof(struct isis_subtlv_spb_mcid);
-        len = len - sizeof(struct isis_subtlv_spb_mcid);
+        tptr = tptr + ISIS_SUBTLV_SPB_MCID_MIN_LEN;
+        len = len - ISIS_SUBTLV_SPB_MCID_MIN_LEN;
+        stlv_len = stlv_len - ISIS_SUBTLV_SPB_MCID_MIN_LEN;
 
         break;
       }
 
       case ISIS_SUBTLV_SPB_DIGEST:
       {
-        ND_TCHECK2(*(tptr), ISIS_SUBTLV_SPB_DIGEST_MIN_LEN);
+        if (stlv_len < ISIS_SUBTLV_SPB_DIGEST_MIN_LEN)
+          goto trunc;
 
         ND_PRINT((ndo, "\n\t        RES: %d V: %d A: %d D: %d",
                         (*(tptr) >> 5), (((*tptr)>> 4) & 0x01),
@@ -1461,18 +1471,15 @@
         }
 
         len = len - ISIS_SUBTLV_SPB_DIGEST_MIN_LEN;
+        stlv_len = stlv_len - ISIS_SUBTLV_SPB_DIGEST_MIN_LEN;
 
         break;
       }
 
       case ISIS_SUBTLV_SPB_BVID:
       {
-        ND_TCHECK2(*(tptr), stlv_len);
-
-        while (len >= ISIS_SUBTLV_SPB_BVID_MIN_LEN)
+        while (stlv_len >= ISIS_SUBTLV_SPB_BVID_MIN_LEN)
         {
-          ND_TCHECK2(*(tptr), ISIS_SUBTLV_SPB_BVID_MIN_LEN);
-
           ND_PRINT((ndo, "\n\t           ECT: %08x",
                       EXTRACT_32BITS(tptr)));
 
@@ -1485,14 +1492,17 @@
 
           tptr = tptr + 2;
           len = len - ISIS_SUBTLV_SPB_BVID_MIN_LEN;
+          stlv_len = stlv_len - ISIS_SUBTLV_SPB_BVID_MIN_LEN;
         }
 
         break;
       }
 
       default:
-          break;
+        break;
     }
+    tptr += stlv_len;
+    len -= stlv_len;
   }
 
   return 0;
@@ -1511,6 +1521,7 @@
 
   while (len > 2)
   {
+    ND_TCHECK2(*tptr, 2);
     stlv_type = *(tptr++);
     stlv_len  = *(tptr++);
 
@@ -1522,11 +1533,17 @@
 
     len = len - 2;
 
+    /* Make sure the subTLV fits within the space left */
+    if (len < stlv_len)
+      goto trunc;
+    /* Make sure the entire subTLV is in the captured data */
+    ND_TCHECK2(*(tptr), stlv_len);
+
     switch (stlv_type)
     {
       case ISIS_SUBTLV_SPB_INSTANCE:
-
-          ND_TCHECK2(*tptr, ISIS_SUBTLV_SPB_INSTANCE_MIN_LEN);
+          if (stlv_len < ISIS_SUBTLV_SPB_INSTANCE_MIN_LEN)
+            goto trunc;
 
           ND_PRINT((ndo, "\n\t        CIST Root-ID: %08x", EXTRACT_32BITS(tptr)));
           tptr = tptr+4;
@@ -1548,10 +1565,12 @@
           tmp = *(tptr++);
 
           len = len - ISIS_SUBTLV_SPB_INSTANCE_MIN_LEN;
+          stlv_len = stlv_len - ISIS_SUBTLV_SPB_INSTANCE_MIN_LEN;
 
           while (tmp)
           {
-            ND_TCHECK2(*tptr, ISIS_SUBTLV_SPB_INSTANCE_VLAN_TUPLE_LEN);
+            if (stlv_len < ISIS_SUBTLV_SPB_INSTANCE_VLAN_TUPLE_LEN)
+              goto trunc;
 
             ND_PRINT((ndo, "\n\t         U:%d, M:%d, A:%d, RES:%d",
                       *(tptr) >> 7, (*(tptr) >> 6) & 0x01,
@@ -1569,14 +1588,15 @@
 
             tptr = tptr + 3;
             len = len - ISIS_SUBTLV_SPB_INSTANCE_VLAN_TUPLE_LEN;
+            stlv_len = stlv_len - ISIS_SUBTLV_SPB_INSTANCE_VLAN_TUPLE_LEN;
             tmp--;
           }
 
           break;
 
       case ISIS_SUBTLV_SPBM_SI:
-
-          ND_TCHECK2(*tptr, 8);
+          if (stlv_len < 8)
+            goto trunc;
 
           ND_PRINT((ndo, "\n\t        BMAC: %08x", EXTRACT_32BITS(tptr)));
           tptr = tptr+4;
@@ -1608,6 +1628,8 @@
       default:
         break;
     }
+    tptr += stlv_len;
+    len -= stlv_len;
   }
   return 0;
 
```
