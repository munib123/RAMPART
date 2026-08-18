# CrossVul Fix Pair: Resource Management Errors in c
**Pair ID:** 1493_0
**Vulnerability Class:** Resource Management Errors
**CWE:** CWE-399
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1493_0`)

## Vulnerability Information & PoC

## Description
Resource Management Errors

## Vulnerable Code
```c
Lines 674-716 of the vulnerable file.


        if (BN_abs_is_word(u, 1))
            break;

        if (BN_num_bits(u) < BN_num_bits(v)) {
            tmp = u;
            u = v;
            v = tmp;
            tmp = b;
            b = c;
            c = tmp;
        }

        if (!BN_GF2m_add(u, u, v))
            goto err;
        if (!BN_GF2m_add(b, b, c))
            goto err;
    }
# else
    {
        int i, ubits = BN_num_bits(u), vbits = BN_num_bits(v), /* v is copy
                                                                * of p */
            top = p->top;
        BN_ULONG *udp, *bdp, *vdp, *cdp;

        bn_wexpand(u, top);
        udp = u->d;
        for (i = u->top; i < top; i++)
            udp[i] = 0;
        u->top = top;
        bn_wexpand(b, top);
        bdp = b->d;
        bdp[0] = 1;
        for (i = 1; i < top; i++)
            bdp[i] = 0;
        b->top = top;
        bn_wexpand(c, top);
        cdp = c->d;
        for (i = 0; i < top; i++)
            cdp[i] = 0;
        c->top = top;
        vdp = v->d;             /* It pays off to "cache" *->d pointers,
                                 * because it allows optimizer to be more
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -691,9 +691,10 @@
     }
 # else
     {
-        int i, ubits = BN_num_bits(u), vbits = BN_num_bits(v), /* v is copy
-                                                                * of p */
-            top = p->top;
+        int i;
+        int ubits = BN_num_bits(u);
+        int vbits = BN_num_bits(v); /* v is copy of p */
+        int top = p->top;
         BN_ULONG *udp, *bdp, *vdp, *cdp;
 
         bn_wexpand(u, top);
@@ -737,8 +738,12 @@
                 ubits--;
             }
 
-            if (ubits <= BN_BITS2 && udp[0] == 1)
-                break;
+            if (ubits <= BN_BITS2) {
+                if (udp[0] == 0) /* poly was reducible */
+                    goto err;
+                if (udp[0] == 1)
+                    break;
+            }
 
             if (ubits < vbits) {
                 i = ubits;
```
