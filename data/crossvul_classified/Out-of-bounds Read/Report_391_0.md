# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 391_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `391_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1346-1391 of the vulnerable file.


        if (bundle->dst.n_bits < 16) {
            VLOG_WARN_RL(&rl, "bundle_load action requires at least 16 bit "
                         "destination.");
            error = OFPERR_OFPBAC_BAD_ARGUMENT;
        }
    } else {
        if (nab->ofs_nbits || nab->dst) {
            VLOG_WARN_RL(&rl, "bundle action has nonzero reserved fields");
            error = OFPERR_OFPBAC_BAD_ARGUMENT;
        }
    }

    if (slaves_size < bundle->n_slaves * sizeof(ovs_be16)) {
        VLOG_WARN_RL(&rl, "Nicira action %s only has %"PRIuSIZE" bytes "
                     "allocated for slaves.  %"PRIuSIZE" bytes are required "
                     "for %"PRIu16" slaves.",
                     load ? "bundle_load" : "bundle", slaves_size,
                     bundle->n_slaves * sizeof(ovs_be16), bundle->n_slaves);
        error = OFPERR_OFPBAC_BAD_LEN;
    }

    for (i = 0; i < bundle->n_slaves; i++) {
        ofp_port_t ofp_port = u16_to_ofp(ntohs(((ovs_be16 *)(nab + 1))[i]));
        ofpbuf_put(ofpacts, &ofp_port, sizeof ofp_port);
        bundle = ofpacts->header;
    }

    ofpact_finish_BUNDLE(ofpacts, &bundle);
    if (!error) {
        error = bundle_check(bundle, OFPP_MAX, NULL);
    }
    return error;
}

static enum ofperr
decode_NXAST_RAW_BUNDLE(const struct nx_action_bundle *nab,
                        enum ofp_version ofp_version OVS_UNUSED,
                        struct ofpbuf *out)
{
    return decode_bundle(false, nab, NULL, NULL, out);
}

static enum ofperr
decode_NXAST_RAW_BUNDLE_LOAD(const struct nx_action_bundle *nab,
                             enum ofp_version ofp_version OVS_UNUSED,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1363,12 +1363,13 @@
                      load ? "bundle_load" : "bundle", slaves_size,
                      bundle->n_slaves * sizeof(ovs_be16), bundle->n_slaves);
         error = OFPERR_OFPBAC_BAD_LEN;
-    }
-
-    for (i = 0; i < bundle->n_slaves; i++) {
-        ofp_port_t ofp_port = u16_to_ofp(ntohs(((ovs_be16 *)(nab + 1))[i]));
-        ofpbuf_put(ofpacts, &ofp_port, sizeof ofp_port);
-        bundle = ofpacts->header;
+    } else {
+        for (i = 0; i < bundle->n_slaves; i++) {
+            ofp_port_t ofp_port
+                = u16_to_ofp(ntohs(((ovs_be16 *)(nab + 1))[i]));
+            ofpbuf_put(ofpacts, &ofp_port, sizeof ofp_port);
+            bundle = ofpacts->header;
+        }
     }
 
     ofpact_finish_BUNDLE(ofpacts, &bundle);
```
