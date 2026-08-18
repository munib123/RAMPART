# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in c
**Pair ID:** 4069_6
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4069_6`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```c
Lines 341-381 of the vulnerable file.

#ifdef USE_SSL
  /* Attempt STLS if available and desired. */
  if (!adata->conn->ssf && (adata->cmd_stls || C_SslForceTls))
  {
    if (C_SslForceTls)
      adata->use_stls = 2;
    if (adata->use_stls == 0)
    {
      enum QuadOption ans =
          query_quadoption(C_SslStarttls, _("Secure connection with TLS?"));
      if (ans == MUTT_ABORT)
        return -2;
      adata->use_stls = 1;
      if (ans == MUTT_YES)
        adata->use_stls = 2;
    }
    if (adata->use_stls == 2)
    {
      mutt_str_strfcpy(buf, "STLS\r\n", sizeof(buf));
      rc = pop_query(adata, buf, sizeof(buf));
      if (rc == -1)
        goto err_conn;
      if (rc != 0)
      {
        mutt_error("%s", adata->err_msg);
      }
      else if (mutt_ssl_starttls(adata->conn))
      {
        mutt_error(_("Could not negotiate TLS connection"));
        return -2;
      }
      else
      {
        /* recheck capabilities after STLS completes */
        rc = pop_capabilities(adata, 1);
        if (rc == -1)
          goto err_conn;
        if (rc == -2)
          return -2;
      }
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -358,6 +358,8 @@
     {
       mutt_str_strfcpy(buf, "STLS\r\n", sizeof(buf));
       rc = pop_query(adata, buf, sizeof(buf));
+      // Clear any data after the STLS acknowledgement
+      mutt_socket_empty(adata->conn);
       if (rc == -1)
         goto err_conn;
       if (rc != 0)
```
