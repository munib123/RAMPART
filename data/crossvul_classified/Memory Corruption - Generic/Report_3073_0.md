# CrossVul Fix Pair: Out-of-bounds Write in c
**Pair ID:** 3073_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-787
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3073_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Write - Typically, this can result in corruption of data, a crash, or code execution.

## Vulnerable Code
```c
Lines 1710-1750 of the vulnerable file.

# define SSL_SESSION_set_app_data(s,a)   (SSL_SESSION_set_ex_data(s,0,(char *)a))
# define SSL_SESSION_get_app_data(s)     (SSL_SESSION_get_ex_data(s,0))
# define SSL_CTX_get_app_data(ctx)       (SSL_CTX_get_ex_data(ctx,0))
# define SSL_CTX_set_app_data(ctx,arg)   (SSL_CTX_set_ex_data(ctx,0,(char *)arg))

/*
 * The following are the possible values for ssl->state are are used to
 * indicate where we are up to in the SSL connection establishment. The
 * macros that follow are about the only things you should need to use and
 * even then, only when using non-blocking IO. It can also be useful to work
 * out where you were when the connection failed
 */

# define SSL_ST_CONNECT                  0x1000
# define SSL_ST_ACCEPT                   0x2000
# define SSL_ST_MASK                     0x0FFF
# define SSL_ST_INIT                     (SSL_ST_CONNECT|SSL_ST_ACCEPT)
# define SSL_ST_BEFORE                   0x4000
# define SSL_ST_OK                       0x03
# define SSL_ST_RENEGOTIATE              (0x04|SSL_ST_INIT)
# define SSL_ST_ERR                      0x05

# define SSL_CB_LOOP                     0x01
# define SSL_CB_EXIT                     0x02
# define SSL_CB_READ                     0x04
# define SSL_CB_WRITE                    0x08
# define SSL_CB_ALERT                    0x4000/* used in callback */
# define SSL_CB_READ_ALERT               (SSL_CB_ALERT|SSL_CB_READ)
# define SSL_CB_WRITE_ALERT              (SSL_CB_ALERT|SSL_CB_WRITE)
# define SSL_CB_ACCEPT_LOOP              (SSL_ST_ACCEPT|SSL_CB_LOOP)
# define SSL_CB_ACCEPT_EXIT              (SSL_ST_ACCEPT|SSL_CB_EXIT)
# define SSL_CB_CONNECT_LOOP             (SSL_ST_CONNECT|SSL_CB_LOOP)
# define SSL_CB_CONNECT_EXIT             (SSL_ST_CONNECT|SSL_CB_EXIT)
# define SSL_CB_HANDSHAKE_START          0x10
# define SSL_CB_HANDSHAKE_DONE           0x20

/* Is the SSL_connection established? */
# define SSL_get_state(a)                SSL_state(a)
# define SSL_is_init_finished(a)         (SSL_state(a) == SSL_ST_OK)
# define SSL_in_init(a)                  (SSL_state(a)&SSL_ST_INIT)
# define SSL_in_before(a)                (SSL_state(a)&SSL_ST_BEFORE)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1727,7 +1727,7 @@
 # define SSL_ST_BEFORE                   0x4000
 # define SSL_ST_OK                       0x03
 # define SSL_ST_RENEGOTIATE              (0x04|SSL_ST_INIT)
-# define SSL_ST_ERR                      0x05
+# define SSL_ST_ERR                      (0x05|SSL_ST_INIT)
 
 # define SSL_CB_LOOP                     0x01
 # define SSL_CB_EXIT                     0x02
```
