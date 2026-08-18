# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 4051_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4051_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 513-553 of the vulnerable file.

	  else
	  {
	    /* RFC 2595 demands we recheck CAPABILITY after TLS completes. */
	    if (imap_exec (idata, "CAPABILITY", 0))
	      goto bail;
	  }
	}
      }
    }

    if (option(OPTSSLFORCETLS) && ! idata->conn->ssf)
    {
      mutt_error _("Encrypted connection unavailable");
      mutt_sleep (1);
      goto err_close_conn;
    }
#endif
  }
  else if (ascii_strncasecmp ("* PREAUTH", idata->buf, 9) == 0)
  {
    idata->state = IMAP_AUTHENTICATED;
    if (imap_check_capabilities (idata) != 0)
      goto bail;
    FREE (&idata->capstr);
  }
  else
  {
    imap_error ("imap_open_connection()", idata->buf);
    goto bail;
  }

  return 0;

#if defined(USE_SSL)
err_close_conn:
  imap_close_connection (idata);
#endif
bail:
  FREE (&idata->capstr);
  return -1;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -530,6 +530,22 @@
   }
   else if (ascii_strncasecmp ("* PREAUTH", idata->buf, 9) == 0)
   {
+#if defined(USE_SSL)
+    /* An unencrypted PREAUTH response is most likely a MITM attack.
+     * Require a confirmation. */
+    if (!idata->conn->ssf)
+    {
+      if (option(OPTSSLFORCETLS) ||
+          (query_quadoption (OPT_SSLSTARTTLS,
+                             _("Abort unencrypted PREAUTH connection?")) != MUTT_NO))
+      {
+        mutt_error _("Encrypted connection unavailable");
+        mutt_sleep (1);
+        goto err_close_conn;
+      }
+    }
+#endif
+
     idata->state = IMAP_AUTHENTICATED;
     if (imap_check_capabilities (idata) != 0)
       goto bail;
```
