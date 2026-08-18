# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in c
**Pair ID:** 4069_5
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4069_5`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```c
Lines 1882-1922 of the vulnerable file.


#ifdef USE_SSL
  /* Attempt STARTTLS if available and desired. */
  if ((adata->use_tls != 1) && (adata->hasSTARTTLS || C_SslForceTls))
  {
    if (adata->use_tls == 0)
    {
      adata->use_tls =
          C_SslForceTls || query_quadoption(C_SslStarttls,
                                            _("Secure connection with TLS?")) == MUTT_YES ?
              2 :
              1;
    }
    if (adata->use_tls == 2)
    {
      if ((mutt_socket_send(conn, "STARTTLS\r\n") < 0) ||
          (mutt_socket_readln(buf, sizeof(buf), conn) < 0))
      {
        return nntp_connect_error(adata);
      }
      if (!mutt_str_startswith(buf, "382", CASE_MATCH))
      {
        adata->use_tls = 0;
        mutt_error("STARTTLS: %s", buf);
      }
      else if (mutt_ssl_starttls(conn))
      {
        adata->use_tls = 0;
        adata->status = NNTP_NONE;
        mutt_socket_close(adata->conn);
        mutt_error(_("Could not negotiate TLS connection"));
        return -1;
      }
      else
      {
        /* recheck capabilities after STARTTLS */
        cap = nntp_capabilities(adata);
        if (cap < 0)
          return -1;
      }
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1899,6 +1899,8 @@
       {
         return nntp_connect_error(adata);
       }
+      // Clear any data after the STARTTLS acknowledgement
+      mutt_socket_empty(conn);
       if (!mutt_str_startswith(buf, "382", CASE_MATCH))
       {
         adata->use_tls = 0;
```
