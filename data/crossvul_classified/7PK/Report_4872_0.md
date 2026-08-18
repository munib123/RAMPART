# CrossVul Fix Pair: 7PK in c
**Pair ID:** 4872_0
**Vulnerability Class:** 7PK
**CWE:** CWE-254
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4872_0`)

## Vulnerability Information & PoC

## Description
7PK - Security Features

## Vulnerable Code
```c
Lines 1252-1293 of the vulnerable file.


    /* We're done when c->multibulk == 0 */
    if (c->multibulklen == 0) return C_OK;

    /* Still not read to process the command */
    return C_ERR;
}

void processInputBuffer(client *c) {
    server.current_client = c;
    /* Keep processing while there is something in the input buffer */
    while(sdslen(c->querybuf)) {
        /* Return if clients are paused. */
        if (!(c->flags & CLIENT_SLAVE) && clientsArePaused()) break;

        /* Immediately abort if the client is in the middle of something. */
        if (c->flags & CLIENT_BLOCKED) break;

        /* CLIENT_CLOSE_AFTER_REPLY closes the connection once the reply is
         * written to the client. Make sure to not let the reply grow after
         * this flag has been set (i.e. don't process more commands). */
        if (c->flags & CLIENT_CLOSE_AFTER_REPLY) break;

        /* Determine request type when unknown. */
        if (!c->reqtype) {
            if (c->querybuf[0] == '*') {
                c->reqtype = PROTO_REQ_MULTIBULK;
            } else {
                c->reqtype = PROTO_REQ_INLINE;
            }
        }

        if (c->reqtype == PROTO_REQ_INLINE) {
            if (processInlineBuffer(c) != C_OK) break;
        } else if (c->reqtype == PROTO_REQ_MULTIBULK) {
            if (processMultibulkBuffer(c) != C_OK) break;
        } else {
            serverPanic("Unknown request type");
        }

        /* Multibulk processing could see a <= 0 length. */
        if (c->argc == 0) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1269,8 +1269,10 @@
 
         /* CLIENT_CLOSE_AFTER_REPLY closes the connection once the reply is
          * written to the client. Make sure to not let the reply grow after
-         * this flag has been set (i.e. don't process more commands). */
-        if (c->flags & CLIENT_CLOSE_AFTER_REPLY) break;
+         * this flag has been set (i.e. don't process more commands).
+         *
+         * The same applies for clients we want to terminate ASAP. */
+        if (c->flags & (CLIENT_CLOSE_AFTER_REPLY|CLIENT_CLOSE_ASAP)) break;
 
         /* Determine request type when unknown. */
         if (!c->reqtype) {
@@ -1637,6 +1639,26 @@
     }
 }
 
+/* This callback is bound to POST and "Host:" command names. Those are not
+ * really commands, but are used in security attacks in order to talk to
+ * Redis instances via HTTP, with a technique called "cross protocol scripting"
+ * which exploits the fact that services like Redis will discard invalid
+ * HTTP headers and will process what follows.
+ *
+ * As a protection against this attack, Redis will terminate the connection
+ * when a POST or "Host:" header is seen, and will log the event from
+ * time to time (to avoid creating a DOS as a result of too many logs). */
+void securityWarningCommand(client *c) {
+    static time_t logged_time;
+    time_t now = time(NULL);
+
+    if (labs(now-logged_time) > 60) {
+        serverLog(LL_WARNING,"Possible SECURITY ATTACK detected. It looks like somebody is sending POST or Host: commands to Redis. This is likely due to an attacker attempting to use Cross Protocol Scripting to compromise your Redis instance. Connection aborted.");
+        logged_time = now;
+    }
+    freeClientAsync(c);
+}
+
 /* Rewrite the command vector of the client. All the new objects ref count
  * is incremented. The old command vector is freed, and the old objects
  * ref count is decremented. */
```
