# CrossVul Fix Pair: Improper Neutralization of Special Elements used in a Command ('Command Injection') in c
**Pair ID:** 248_0
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-77
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `248_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in a Command ('Command Injection') - Command injection vulnerabilities typically occur when: 1.

## Vulnerable Code
```c
Lines 1692-1732 of the vulnerable file.


  FREE(&buf.data);
  return 0;
}

/**
 * imap_subscribe - Subscribe to a mailbox
 * @param path      Mailbox path
 * @param subscribe True: subscribe, false: unsubscribe
 * @retval  0 Success
 * @retval -1 Failure
 */
int imap_subscribe(char *path, bool subscribe)
{
  struct ImapData *idata = NULL;
  char buf[LONG_STRING];
  char mbox[LONG_STRING];
  char errstr[STRING];
  struct Buffer err, token;
  struct ImapMbox mx;

  if (!mx_is_imap(path) || imap_parse_path(path, &mx) || !mx.mbox)
  {
    mutt_error(_("Bad mailbox name"));
    return -1;
  }
  idata = imap_conn_find(&(mx.account), 0);
  if (!idata)
    goto fail;

  imap_fix_path(idata, mx.mbox, buf, sizeof(buf));
  if (!*buf)
    mutt_str_strfcpy(buf, "INBOX", sizeof(buf));

  if (ImapCheckSubscribed)
  {
    mutt_buffer_init(&token);
    mutt_buffer_init(&err);
    err.data = errstr;
    err.dsize = sizeof(errstr);
    snprintf(mbox, sizeof(mbox), "%smailboxes \"%s\"", subscribe ? "" : "un", path);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1709,6 +1709,7 @@
   char errstr[STRING];
   struct Buffer err, token;
   struct ImapMbox mx;
+  size_t len = 0;
 
   if (!mx_is_imap(path) || imap_parse_path(path, &mx) || !mx.mbox)
   {
@@ -1729,7 +1730,8 @@
     mutt_buffer_init(&err);
     err.data = errstr;
     err.dsize = sizeof(errstr);
-    snprintf(mbox, sizeof(mbox), "%smailboxes \"%s\"", subscribe ? "" : "un", path);
+	len = snprintf(mbox, sizeof(mbox), "%smailboxes ", subscribe ? "" : "un");
+	imap_quote_string(mbox + len, sizeof(mbox) - len, path, true);
     if (mutt_parse_rc_line(mbox, &token, &err))
       mutt_debug(1, "Error adding subscribed mailbox: %s\n", errstr);
     FREE(&token.data);
```
