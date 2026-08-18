# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in c
**Pair ID:** 4069_3
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4069_3`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```c
Lines 722-762 of the vulnerable file.

    if (!mutt_str_startswith(adata->buf, "* OK [CAPABILITY", CASE_IGNORE) &&
        check_capabilities(adata))
    {
      goto bail;
    }
#ifdef USE_SSL
    /* Attempt STARTTLS if available and desired. */
    if (!adata->conn->ssf && (C_SslForceTls || (adata->capabilities & IMAP_CAP_STARTTLS)))
    {
      enum QuadOption ans;

      if (C_SslForceTls)
        ans = MUTT_YES;
      else if ((ans = query_quadoption(C_SslStarttls,
                                       _("Secure connection with TLS?"))) == MUTT_ABORT)
      {
        goto err_close_conn;
      }
      if (ans == MUTT_YES)
      {
        enum ImapExecResult rc = imap_exec(adata, "STARTTLS", IMAP_CMD_NO_FLAGS);
        if (rc == IMAP_EXEC_FATAL)
          goto bail;
        if (rc != IMAP_EXEC_ERROR)
        {
          if (mutt_ssl_starttls(adata->conn))
          {
            mutt_error(_("Could not negotiate TLS connection"));
            goto err_close_conn;
          }
          else
          {
            /* RFC2595 demands we recheck CAPABILITY after TLS completes. */
            if (imap_exec(adata, "CAPABILITY", IMAP_CMD_NO_FLAGS))
              goto bail;
          }
        }
      }
    }

    if (C_SslForceTls && !adata->conn->ssf)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -739,7 +739,10 @@
       }
       if (ans == MUTT_YES)
       {
-        enum ImapExecResult rc = imap_exec(adata, "STARTTLS", IMAP_CMD_NO_FLAGS);
+        enum ImapExecResult rc = imap_exec(adata, "STARTTLS", IMAP_CMD_SINGLE);
+        // Clear any data after the STARTTLS acknowledgement
+        mutt_socket_empty(adata->conn);
+
         if (rc == IMAP_EXEC_FATAL)
           goto bail;
         if (rc != IMAP_EXEC_ERROR)
```
