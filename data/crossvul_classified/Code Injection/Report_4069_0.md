# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in c
**Pair ID:** 4069_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4069_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```c
Lines 284-303 of the vulnerable file.

  {
    mutt_tunnel_socket_setup(conn);
  }
  else if (type == MUTT_CONNECTION_SSL)
  {
    int rc = mutt_ssl_socket_setup(conn);
    if (rc < 0)
      FREE(&conn);
  }
  else
  {
    conn->read = raw_socket_read;
    conn->write = raw_socket_write;
    conn->open = raw_socket_open;
    conn->close = raw_socket_close;
    conn->poll = raw_socket_poll;
  }

  return conn;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -301,3 +301,23 @@
 
   return conn;
 }
+
+/**
+ * mutt_socket_empty - Clear out any queued data
+ *
+ * The internal buffer is emptied and any data that has already arrived at this
+ * machine (in kernel buffers) is read and dropped.
+ */
+void mutt_socket_empty(struct Connection *conn)
+{
+  if (!conn)
+    return;
+
+  char buf[1024];
+  int bytes;
+
+  while ((bytes = mutt_socket_poll(conn, 0)) > 0)
+  {
+    mutt_socket_read(conn, buf, MIN(bytes, sizeof(buf)));
+  }
+}
```
