# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in c
**Pair ID:** 4069_7
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4069_7`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```c
Lines 702-742 of the vulnerable file.

    return rc;

#ifdef USE_SSL
  enum QuadOption ans = MUTT_NO;
  if (conn->ssf)
    ans = MUTT_NO;
  else if (C_SslForceTls)
    ans = MUTT_YES;
  else if ((Capabilities & SMTP_CAP_STARTTLS) &&
           ((ans = query_quadoption(C_SslStarttls,
                                    _("Secure connection with TLS?"))) == MUTT_ABORT))
  {
    return -1;
  }

  if (ans == MUTT_YES)
  {
    if (mutt_socket_send(conn, "STARTTLS\r\n") < 0)
      return SMTP_ERR_WRITE;
    rc = smtp_get_resp(conn);
    if (rc != 0)
      return rc;

    if (mutt_ssl_starttls(conn))
    {
      mutt_error(_("Could not negotiate TLS connection"));
      return -1;
    }

    /* re-EHLO to get authentication mechanisms */
    rc = smtp_helo(conn, esmtp);
    if (rc != 0)
      return rc;
  }
#endif

  if (conn->account.flags & MUTT_ACCT_USER)
  {
    if (!(Capabilities & SMTP_CAP_AUTH))
    {
      mutt_error(_("SMTP server does not support authentication"));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -719,6 +719,8 @@
     if (mutt_socket_send(conn, "STARTTLS\r\n") < 0)
       return SMTP_ERR_WRITE;
     rc = smtp_get_resp(conn);
+    // Clear any data after the STARTTLS acknowledgement
+    mutt_socket_empty(conn);
     if (rc != 0)
       return rc;
 
```
