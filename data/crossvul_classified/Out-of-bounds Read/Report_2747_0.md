# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 2747_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2747_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 342-383 of the vulnerable file.

            EXTRACT_16BITS(ptr.common->packet_seq),
            length));

    tptr += sizeof(struct olsr_common);

    /*
     * In non-verbose mode, just print version.
     */
    if (ndo->ndo_vflag < 1) {
        return;
    }

    while (tptr < (pptr+length)) {
        union
        {
            const struct olsr_msg4 *v4;
            const struct olsr_msg6 *v6;
        } msgptr;
        int msg_len_valid = 0;

        ND_TCHECK2(*tptr, sizeof(struct olsr_msg4));

        if (is_ipv6)
        {
            msgptr.v6 = (const struct olsr_msg6 *) tptr;
            msg_type = msgptr.v6->msg_type;
            msg_len = EXTRACT_16BITS(msgptr.v6->msg_len);
            if ((msg_len >= sizeof (struct olsr_msg6))
                    && (msg_len <= length))
                msg_len_valid = 1;

            /* infinite loop check */
            if (msg_type == 0 || msg_len == 0) {
                return;
            }

            ND_PRINT((ndo, "\n\t%s Message (%#04x), originator %s, ttl %u, hop %u"
                    "\n\t  vtime %.3fs, msg-seq 0x%04x, length %u%s",
                    tok2str(olsr_msg_values, "Unknown", msg_type),
                    msg_type, ip6addr_string(ndo, msgptr.v6->originator),
                    msgptr.v6->ttl,
                    msgptr.v6->hopcount,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -359,10 +359,9 @@
         } msgptr;
         int msg_len_valid = 0;
 
-        ND_TCHECK2(*tptr, sizeof(struct olsr_msg4));
-
         if (is_ipv6)
         {
+            ND_TCHECK2(*tptr, sizeof(struct olsr_msg6));
             msgptr.v6 = (const struct olsr_msg6 *) tptr;
             msg_type = msgptr.v6->msg_type;
             msg_len = EXTRACT_16BITS(msgptr.v6->msg_len);
@@ -393,6 +392,7 @@
         }
         else /* (!is_ipv6) */
         {
+            ND_TCHECK2(*tptr, sizeof(struct olsr_msg4));
             msgptr.v4 = (const struct olsr_msg4 *) tptr;
             msg_type = msgptr.v4->msg_type;
             msg_len = EXTRACT_16BITS(msgptr.v4->msg_len);
@@ -616,21 +616,24 @@
 
         case OLSR_NAMESERVICE_MSG:
         {
-            u_int name_entries = EXTRACT_16BITS(msg_data+2);
-            u_int addr_size = 4;
-            int name_entries_valid = 0;
+            u_int name_entries;
+            u_int addr_size;
+            int name_entries_valid;
             u_int i;
 
+            if (msg_tlen < 4)
+                goto trunc;
+            ND_TCHECK2(*msg_data, 4);
+
+            name_entries = EXTRACT_16BITS(msg_data+2);
+            addr_size = 4;
             if (is_ipv6)
                 addr_size = 16;
 
+            name_entries_valid = 0;
             if ((name_entries > 0)
                     && ((name_entries * (4 + addr_size)) <= msg_tlen))
                 name_entries_valid = 1;
-
-            if (msg_tlen < 4)
-                goto trunc;
-            ND_TCHECK2(*msg_data, 4);
 
             ND_PRINT((ndo, "\n\t  Version %u, Entries %u%s",
                    EXTRACT_16BITS(msg_data),
```
