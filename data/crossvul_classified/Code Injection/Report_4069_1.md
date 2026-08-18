# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in c
**Pair ID:** 4069_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4069_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```c
Lines 22-51 of the vulnerable file.

 */

#ifndef MUTT_CONN_SOCKET_H
#define MUTT_CONN_SOCKET_H

#include <time.h>

struct Connection;

/**
 * enum ConnectionType - Type of connection
 */
enum ConnectionType
{
  MUTT_CONNECTION_SIMPLE, ///< Simple TCP socket connection
  MUTT_CONNECTION_TUNNEL, ///< Tunnelled connection
  MUTT_CONNECTION_SSL,    ///< SSL/TLS-encrypted connection
};

int                mutt_socket_close   (struct Connection *conn);
struct Connection *mutt_socket_new     (enum ConnectionType type);
int                mutt_socket_open    (struct Connection *conn);
int                mutt_socket_poll    (struct Connection *conn, time_t wait_secs);
int                mutt_socket_read    (struct Connection *conn, char *buf, size_t len);
int                mutt_socket_readchar(struct Connection *conn, char *c);
int                mutt_socket_readln_d(char *buf, size_t buflen, struct Connection *conn, int dbg);
int                mutt_socket_write   (struct Connection *conn, const char *buf, size_t len);
int                mutt_socket_write_d (struct Connection *conn, const char *buf, int len, int dbg);

#endif /* MUTT_CONN_SOCKET_H */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -39,6 +39,7 @@
 };
 
 int                mutt_socket_close   (struct Connection *conn);
+void               mutt_socket_empty   (struct Connection *conn);
 struct Connection *mutt_socket_new     (enum ConnectionType type);
 int                mutt_socket_open    (struct Connection *conn);
 int                mutt_socket_poll    (struct Connection *conn, time_t wait_secs);
```
