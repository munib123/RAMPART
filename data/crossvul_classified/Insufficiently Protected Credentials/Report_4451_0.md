# CrossVul Fix Pair: Insufficiently Protected Credentials in c
**Pair ID:** 4451_0
**Vulnerability Class:** Insufficiently Protected Credentials
**CWE:** CWE-522
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4451_0`)

## Vulnerability Information & PoC

## Description
Insufficiently Protected Credentials - The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.

## Vulnerable Code
```c
Lines 744-784 of the vulnerable file.

    return -1;
  }

  if (mutt_istr_startswith(adata->buf, "* OK"))
  {
    if (!mutt_istr_startswith(adata->buf, "* OK [CAPABILITY") && check_capabilities(adata))
    {
      goto bail;
    }
#ifdef USE_SSL
    /* Attempt STARTTLS if available and desired. */
    if ((adata->conn->ssf == 0) && (C_SslForceTls || (adata->capabilities & IMAP_CAP_STARTTLS)))
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
        enum ImapExecResult rc = imap_exec(adata, "STARTTLS", IMAP_CMD_SINGLE);
        // Clear any data after the STARTTLS acknowledgement
        mutt_socket_empty(adata->conn);

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
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -761,7 +761,7 @@
       else if ((ans = query_quadoption(C_SslStarttls,
                                        _("Secure connection with TLS?"))) == MUTT_ABORT)
       {
-        goto err_close_conn;
+        goto bail;
       }
       if (ans == MUTT_YES)
       {
@@ -776,7 +776,7 @@
           if (mutt_ssl_starttls(adata->conn))
           {
             mutt_error(_("Could not negotiate TLS connection"));
-            goto err_close_conn;
+            goto bail;
           }
           else
           {
@@ -791,7 +791,7 @@
     if (C_SslForceTls && (adata->conn->ssf == 0))
     {
       mutt_error(_("Encrypted connection unavailable"));
-      goto err_close_conn;
+      goto bail;
     }
 #endif
   }
@@ -807,7 +807,7 @@
     if ((adata->conn->ssf == 0) && C_SslForceTls)
     {
       mutt_error(_("Encrypted connection unavailable"));
-      goto err_close_conn;
+      goto bail;
     }
 #endif
 
@@ -824,11 +824,8 @@
 
   return 0;
 
-#ifdef USE_SSL
-err_close_conn:
+bail:
   imap_close_connection(adata);
-#endif
-bail:
   FREE(&adata->capstr);
   return -1;
 }
```
