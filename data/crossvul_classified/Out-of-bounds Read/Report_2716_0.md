# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2716_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2716_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 161-201 of the vulnerable file.

        uint8_t        len;
        uint8_t        sub_b;
        uint8_t        addr_id;
};

#define MP_PRIO_B                       0x01

static int
dummy_print(netdissect_options *ndo _U_,
            const u_char *opt _U_, u_int opt_len _U_, u_char flags _U_)
{
        return 1;
}

static int
mp_capable_print(netdissect_options *ndo,
                 const u_char *opt, u_int opt_len, u_char flags)
{
        const struct mp_capable *mpc = (const struct mp_capable *) opt;

        if (!(opt_len == 12 && flags & TH_SYN) &&
            !(opt_len == 20 && (flags & (TH_SYN | TH_ACK)) == TH_ACK))
                return 0;

        if (MP_CAPABLE_OPT_VERSION(mpc->sub_ver) != 0) {
                ND_PRINT((ndo, " Unknown Version (%d)", MP_CAPABLE_OPT_VERSION(mpc->sub_ver)));
                return 1;
        }

        if (mpc->flags & MP_CAPABLE_C)
                ND_PRINT((ndo, " csum"));
        ND_PRINT((ndo, " {0x%" PRIx64, EXTRACT_64BITS(mpc->sender_key)));
        if (opt_len == 20) /* ACK */
                ND_PRINT((ndo, ",0x%" PRIx64, EXTRACT_64BITS(mpc->receiver_key)));
        ND_PRINT((ndo, "}"));
        return 1;
}

static int
mp_join_print(netdissect_options *ndo,
              const u_char *opt, u_int opt_len, u_char flags)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -178,7 +178,7 @@
 {
         const struct mp_capable *mpc = (const struct mp_capable *) opt;
 
-        if (!(opt_len == 12 && flags & TH_SYN) &&
+        if (!(opt_len == 12 && (flags & TH_SYN)) &&
             !(opt_len == 20 && (flags & (TH_SYN | TH_ACK)) == TH_ACK))
                 return 0;
 
@@ -202,9 +202,9 @@
 {
         const struct mp_join *mpj = (const struct mp_join *) opt;
 
-        if (!(opt_len == 12 && flags & TH_SYN) &&
+        if (!(opt_len == 12 && (flags & TH_SYN)) &&
             !(opt_len == 16 && (flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)) &&
-            !(opt_len == 24 && flags & TH_ACK))
+            !(opt_len == 24 && (flags & TH_ACK)))
                 return 0;
 
         if (opt_len != 24) {
@@ -236,76 +236,92 @@
         return 1;
 }
 
-static u_int mp_dss_len(const  struct mp_dss *m, int csum)
-{
-        u_int len;
-
-        len = 4;
-        if (m->flags & MP_DSS_A) {
-                /* Ack present - 4 or 8 octets */
-                len += (m->flags & MP_DSS_a) ? 8 : 4;
-        }
-        if (m->flags & MP_DSS_M) {
+static int
+mp_dss_print(netdissect_options *ndo,
+             const u_char *opt, u_int opt_len, u_char flags)
+{
+        const struct mp_dss *mdss = (const struct mp_dss *) opt;
+
+        /* We need the flags, at a minimum. */
+        if (opt_len < 4)
+                return 0;
+
+        if (flags & TH_SYN)
+                return 0;
+
+        if (mdss->flags & MP_DSS_F)
+                ND_PRINT((ndo, " fin"));
+
+        opt += 4;
+        opt_len -= 4;
+        if (mdss->flags & MP_DSS_A) {
+                /* Ack present */
+                ND_PRINT((ndo, " ack "));
+                /*
+                 * If the a flag is set, we have an 8-byte ack; if it's
+                 * clear, we have a 4-byte ack.
+                 */
+                if (mdss->flags & MP_DSS_a) {
+                        if (opt_len < 8)
+                                return 0;
+                        ND_PRINT((ndo, "%" PRIu64, EXTRACT_64BITS(opt)));
+                        opt += 8;
+                        opt_len -= 8;
+                } else {
+                        if (opt_len < 4)
+                                return 0;
+                        ND_PRINT((ndo, "%u", EXTRACT_32BITS(opt)));
+                        opt += 4;
+                        opt_len -= 4;
+                }
+        }
+
+        if (mdss->flags & MP_DSS_M) {
                 /*
                  * Data Sequence Number (DSN), Subflow Sequence Number (SSN),
                  * Data-Level Length present, and Checksum possibly present.
-                 * All but the Checksum are 10 bytes if the m flag is
-                 * clear (4-byte DSN) and 14 bytes if the m flag is set
-                 * (8-byte DSN).
                  */
-                len += (m->flags & MP_DSS_m) ? 14 : 10;
+                ND_PRINT((ndo, " seq "));
+		/*
+                 * If the m flag is set, we have an 8-byte NDS; if it's clear,
+                 * we have a 4-byte DSN.
+                 */
+                if (mdss->flags & MP_DSS_m) {
+                        if (opt_len < 8)
+                                return 0;
+                        ND_PRINT((ndo, "%" PRIu64, EXTRACT_64BITS(opt)));
+                        opt += 8;
+                        opt_len -= 8;
+                } else {
+                        if (opt_len < 4)
+                                return 0;
+                        ND_PRINT((ndo, "%u", EXTRACT_32BITS(opt)));
+                        opt += 4;
+                        opt_len -= 4;
+                }
+                if (opt_len < 4)
+                        return 0;
+                ND_PRINT((ndo, " subseq %u", EXTRACT_32BITS(opt)));
+                opt += 4;
+                opt_len -= 4;
+                if (opt_len < 2)
+                        return 0;
+                ND_PRINT((ndo, " len %u", EXTRACT_16BITS(opt)));
+                opt += 2;
+                opt_len -= 2;
 
                 /*
                  * The Checksum is present only if negotiated.
+                 * If there are at least 2 bytes left, process the next 2
+                 * bytes as the Checksum.
                  */
-                if (csum)
-                        len += 2;
-	}
-	return len;
-}
-
-static int
-mp_dss_print(netdissect_options *ndo,
-             const u_char *opt, u_int opt_len, u_char flags)
-{
-        const struct mp_dss *mdss = (const struct mp_dss *) opt;
-
-        if ((opt_len != mp_dss_len(mdss, 1) &&
-             opt_len != mp_dss_len(mdss, 0)) || flags & TH_SYN)
-                return 0;
-
-        if (mdss->flags & MP_DSS_F)
-                ND_PRINT((ndo, " fin"));
-
-        opt += 4;
-        if (mdss->flags & MP_DSS_A) {
-                ND_PRINT((ndo, " ack "));
-                if (mdss->flags & MP_DSS_a) {
-                        ND_PRINT((ndo, "%" PRIu64, EXTRACT_64BITS(opt)));
-                        opt += 8;
-                } else {
-                        ND_PRINT((ndo, "%u", EXTRACT_32BITS(opt)));
-                        opt += 4;
+                if (opt_len >= 2) {
+                        ND_PRINT((ndo, " csum 0x%x", EXTRACT_16BITS(opt)));
+                        opt_len -= 2;
                 }
         }
-
-        if (mdss->flags & MP_DSS_M) {
-                ND_PRINT((ndo, " seq "));
-                if (mdss->flags & MP_DSS_m) {
-                        ND_PRINT((ndo, "%" PRIu64, EXTRACT_64BITS(opt)));
-                        opt += 8;
-                } else {
-                        ND_PRINT((ndo, "%u", EXTRACT_32BITS(opt)));
-                        opt += 4;
-                }
-                ND_PRINT((ndo, " subseq %u", EXTRACT_32BITS(opt)));
-                opt += 4;
-                ND_PRINT((ndo, " len %u", EXTRACT_16BITS(opt)));
-                opt += 2;
-
-                if (opt_len == mp_dss_len(mdss, 1))
-                        ND_PRINT((ndo, " csum 0x%x", EXTRACT_16BITS(opt)));
-        }
+        if (opt_len != 0)
+                return 0;
         return 1;
 }
 
```
