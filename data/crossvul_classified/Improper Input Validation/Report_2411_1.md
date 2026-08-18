# CrossVul Fix Pair: Improper Input Validation in cpp
**Pair ID:** 2411_1
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2411_1`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```cpp
Lines 306-346 of the vulnerable file.

    zap_pipe = new_pipes [0];
    zap_pipe->set_nodelay ();
    zap_pipe->set_event_sink (this);

    send_bind (peer.socket, new_pipes [1], false);

    //  Send empty identity if required by the peer.
    if (peer.options.recv_identity) {
        msg_t id;
        rc = id.init ();
        errno_assert (rc == 0);
        id.set_flags (msg_t::identity);
        bool ok = zap_pipe->write (&id);
        zmq_assert (ok);
        zap_pipe->flush ();
    }

    return 0;
}

void zmq::session_base_t::process_attach (i_engine *engine_)
{
    zmq_assert (engine_ != NULL);

    //  Create the pipe if it does not exist yet.
    if (!pipe && !is_terminating ()) {
        object_t *parents [2] = {this, socket};
        pipe_t *pipes [2] = {NULL, NULL};

        bool conflate = options.conflate &&
            (options.type == ZMQ_DEALER ||
             options.type == ZMQ_PULL ||
             options.type == ZMQ_PUSH ||
             options.type == ZMQ_PUB ||
             options.type == ZMQ_SUB);

        int hwms [2] = {conflate? -1 : options.rcvhwm,
            conflate? -1 : options.sndhwm};
        bool conflates [2] = {conflate, conflate};
        int rc = pipepair (parents, pipes, hwms, conflates);
        errno_assert (rc == 0);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -323,6 +323,14 @@
     return 0;
 }
 
+bool zmq::session_base_t::zap_enabled ()
+{
+    return (
+         options.mechanism != ZMQ_NULL ||
+        (options.mechanism == ZMQ_NULL && options.zap_domain.length() > 0)
+    );
+}
+
 void zmq::session_base_t::process_attach (i_engine *engine_)
 {
     zmq_assert (engine_ != NULL);
```
