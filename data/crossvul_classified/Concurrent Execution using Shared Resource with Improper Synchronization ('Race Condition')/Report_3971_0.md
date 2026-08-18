# CrossVul Fix Pair: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') in c
**Pair ID:** 3971_0
**Vulnerability Class:** Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
**CWE:** CWE-362
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3971_0`)

## Vulnerability Information & PoC

## Description
Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition') - This can have security implications when the expected synchronization is in security-critical code, such as recording whether a user is authenticated or modifying important state information that s...

## Vulnerable Code
```c
Lines 2560-2600 of the vulnerable file.


            /* transfer from-addr from top-level context buffer to instance */
            if (!floated)
            {
                c->c2.from = m->top.c2.from;
            }
        }

        if (BLEN(&c->c2.buf) > 0)
        {
            struct link_socket_info *lsi;
            const uint8_t *orig_buf;

            /* decrypt in instance context */

            perf_push(PERF_PROC_IN_LINK);
            lsi = get_link_socket_info(c);
            orig_buf = c->c2.buf.data;
            if (process_incoming_link_part1(c, lsi, floated))
            {
                if (floated)
                {
                    multi_process_float(m, m->pending);
                }

                process_incoming_link_part2(c, lsi, orig_buf);
            }
            perf_pop();

            if (TUNNEL_TYPE(m->top.c1.tuntap) == DEV_TYPE_TUN)
            {
                /* extract packet source and dest addresses */
                mroute_flags = mroute_extract_addr_from_packet(&src,
                                                               &dest,
                                                               NULL,
                                                               NULL,
                                                               0,
                                                               &c->c2.to_tun,
                                                               DEV_TYPE_TUN);

                /* drop packet if extract failed */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2577,7 +2577,8 @@
             orig_buf = c->c2.buf.data;
             if (process_incoming_link_part1(c, lsi, floated))
             {
-                if (floated)
+                /* nonzero length means that we have a valid, decrypted packed */
+                if (floated && c->c2.buf.len > 0)
                 {
                     multi_process_float(m, m->pending);
                 }
```
