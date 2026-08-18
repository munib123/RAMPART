# CrossVul Fix Pair: Reachable Assertion in c
**Pair ID:** 2488_1
**Vulnerability Class:** Reachable Assertion
**CWE:** CWE-617
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2488_1`)

## Vulnerability Information & PoC

## Description
Reachable Assertion - While assertion is good for catching logic errors and reducing the chances of reaching more serious vulnerability conditions, it can still lead to a denial of service.

## Vulnerable Code
```c
Lines 3074-3114 of the vulnerable file.

 * If it's a rendezvous stream, call connection_exit_connect() on
 * it.
 *
 * For general streams, call dns_resolve() on it first, and only call
 * connection_exit_connect() if the dns answer is already known.
 *
 * Note that we don't call connection_add() on the new stream! We wait
 * for connection_exit_connect() to do that.
 *
 * Return -(some circuit end reason) if we want to tear down <b>circ</b>.
 * Else return 0.
 */
int
connection_exit_begin_conn(cell_t *cell, circuit_t *circ)
{
  edge_connection_t *n_stream;
  relay_header_t rh;
  char *address = NULL;
  uint16_t port = 0;
  or_circuit_t *or_circ = NULL;
  const or_options_t *options = get_options();
  begin_cell_t bcell;
  int rv;
  uint8_t end_reason=0;

  assert_circuit_ok(circ);
  if (!CIRCUIT_IS_ORIGIN(circ))
    or_circ = TO_OR_CIRCUIT(circ);

  relay_header_unpack(&rh, cell->payload);
  if (rh.length > RELAY_PAYLOAD_SIZE)
    return -END_CIRC_REASON_TORPROTOCOL;

  /* Note: we have to use relay_send_command_from_edge here, not
   * connection_edge_end or connection_edge_send_command, since those require
   * that we have a stream connected to a circuit, and we don't connect to a
   * circuit until we have a pending/successful resolve. */

  if (!server_mode(options) &&
      circ->purpose != CIRCUIT_PURPOSE_S_REND_JOINED) {
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3091,14 +3091,21 @@
   char *address = NULL;
   uint16_t port = 0;
   or_circuit_t *or_circ = NULL;
+  origin_circuit_t *origin_circ = NULL;
+  crypt_path_t *layer_hint = NULL;
   const or_options_t *options = get_options();
   begin_cell_t bcell;
   int rv;
   uint8_t end_reason=0;
 
   assert_circuit_ok(circ);
-  if (!CIRCUIT_IS_ORIGIN(circ))
+  if (!CIRCUIT_IS_ORIGIN(circ)) {
     or_circ = TO_OR_CIRCUIT(circ);
+  } else {
+    tor_assert(circ->purpose == CIRCUIT_PURPOSE_S_REND_JOINED);
+    origin_circ = TO_ORIGIN_CIRCUIT(circ);
+    layer_hint = origin_circ->cpath->prev;
+  }
 
   relay_header_unpack(&rh, cell->payload);
   if (rh.length > RELAY_PAYLOAD_SIZE)
@@ -3123,7 +3130,7 @@
     return -END_CIRC_REASON_TORPROTOCOL;
   } else if (rv == -1) {
     tor_free(bcell.address);
-    relay_send_end_cell_from_edge(rh.stream_id, circ, end_reason, NULL);
+    relay_send_end_cell_from_edge(rh.stream_id, circ, end_reason, layer_hint);
     return 0;
   }
 
@@ -3160,7 +3167,7 @@
     if (!directory_permits_begindir_requests(options) ||
         circ->purpose != CIRCUIT_PURPOSE_OR) {
       relay_send_end_cell_from_edge(rh.stream_id, circ,
-                                    END_STREAM_REASON_NOTDIRECTORY, NULL);
+                                  END_STREAM_REASON_NOTDIRECTORY, layer_hint);
       return 0;
     }
     /* Make sure to get the 'real' address of the previous hop: the
@@ -3177,7 +3184,7 @@
   } else {
     log_warn(LD_BUG, "Got an unexpected command %d", (int)rh.command);
     relay_send_end_cell_from_edge(rh.stream_id, circ,
-                                  END_STREAM_REASON_INTERNAL, NULL);
+                                  END_STREAM_REASON_INTERNAL, layer_hint);
     return 0;
   }
 
@@ -3188,7 +3195,7 @@
     if (bcell.flags & BEGIN_FLAG_IPV4_NOT_OK) {
       tor_free(address);
       relay_send_end_cell_from_edge(rh.stream_id, circ,
-                                    END_STREAM_REASON_EXITPOLICY, NULL);
+                                    END_STREAM_REASON_EXITPOLICY, layer_hint);
       return 0;
     }
   }
@@ -3211,7 +3218,7 @@
   n_stream->deliver_window = STREAMWINDOW_START;
 
   if (circ->purpose == CIRCUIT_PURPOSE_S_REND_JOINED) {
-    origin_circuit_t *origin_circ = TO_ORIGIN_CIRCUIT(circ);
+    tor_assert(origin_circ);
     log_info(LD_REND,"begin is for rendezvous. configuring stream.");
     n_stream->base_.address = tor_strdup("(rendezvous)");
     n_stream->base_.state = EXIT_CONN_STATE_CONNECTING;
@@ -3231,7 +3238,7 @@
        * the hidden service. */
       relay_send_end_cell_from_edge(rh.stream_id, circ,
                                     END_STREAM_REASON_DONE,
-                                    origin_circ->cpath->prev);
+                                    layer_hint);
       connection_free(TO_CONN(n_stream));
       tor_free(address);
 
```
