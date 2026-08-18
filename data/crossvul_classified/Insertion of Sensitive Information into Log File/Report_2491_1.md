# CrossVul Fix Pair: Insertion of Sensitive Information into Log File in c
**Pair ID:** 2491_1
**Vulnerability Class:** Insertion of Sensitive Information into Log File
**CWE:** CWE-532
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2491_1`)

## Vulnerability Information & PoC

## Description
Insertion of Sensitive Information into Log File - While logging all information may be helpful during development stages, it is important that logging levels be set appropriately before a product ships so that sensitive user data and system inform...

## Vulnerable Code
```c
Lines 3355-3395 of the vulnerable file.

  rend_intro_point_t *intro;
  char serviceid[REND_SERVICE_ID_LEN_BASE32+1];
  (void) request;
  (void) request_len;
  tor_assert(circuit->rend_data);
  /* XXX: This is version 2 specific (only supported one for now). */
  const char *rend_pk_digest =
    (char *) rend_data_get_pk_digest(circuit->rend_data, NULL);

  if (circuit->base_.purpose != CIRCUIT_PURPOSE_S_ESTABLISH_INTRO) {
    log_warn(LD_PROTOCOL,
             "received INTRO_ESTABLISHED cell on non-intro circuit.");
    goto err;
  }
  service = rend_service_get_by_pk_digest(rend_pk_digest);
  if (!service) {
    log_warn(LD_REND, "Unknown service on introduction circuit %u.",
             (unsigned)circuit->base_.n_circ_id);
    goto err;
  }
  /* We've just successfully established a intro circuit to one of our
   * introduction point, account for it. */
  intro = find_intro_point(circuit);
  if (intro == NULL) {
    log_warn(LD_REND,
             "Introduction circuit established without a rend_intro_point_t "
             "object for service %s on circuit %u",
             safe_str_client(serviceid), (unsigned)circuit->base_.n_circ_id);
    goto err;
  }
  intro->circuit_established = 1;
  /* We might not have every introduction point ready but at this point we
   * know that the descriptor needs to be uploaded. */
  service->desc_is_dirty = time(NULL);
  circuit_change_purpose(TO_CIRCUIT(circuit), CIRCUIT_PURPOSE_S_INTRO);

  base32_encode(serviceid, REND_SERVICE_ID_LEN_BASE32 + 1,
                rend_pk_digest, REND_SERVICE_ID_LEN);
  log_info(LD_REND,
           "Received INTRO_ESTABLISHED cell on circuit %u for service %s",
           (unsigned)circuit->base_.n_circ_id, serviceid);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3372,6 +3372,8 @@
              (unsigned)circuit->base_.n_circ_id);
     goto err;
   }
+  base32_encode(serviceid, REND_SERVICE_ID_LEN_BASE32 + 1,
+                rend_pk_digest, REND_SERVICE_ID_LEN);
   /* We've just successfully established a intro circuit to one of our
    * introduction point, account for it. */
   intro = find_intro_point(circuit);
@@ -3388,8 +3390,6 @@
   service->desc_is_dirty = time(NULL);
   circuit_change_purpose(TO_CIRCUIT(circuit), CIRCUIT_PURPOSE_S_INTRO);
 
-  base32_encode(serviceid, REND_SERVICE_ID_LEN_BASE32 + 1,
-                rend_pk_digest, REND_SERVICE_ID_LEN);
   log_info(LD_REND,
            "Received INTRO_ESTABLISHED cell on circuit %u for service %s",
            (unsigned)circuit->base_.n_circ_id, serviceid);
```
