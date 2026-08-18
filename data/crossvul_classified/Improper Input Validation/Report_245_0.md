# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 245_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `245_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 618-658 of the vulnerable file.

{
  char *value = NULL;
  struct Buffy *inc = NULL;
  struct ImapMbox mx;
  struct ImapStatus *status = NULL;
  unsigned int olduv, oldun;
  unsigned int litlen;
  short new = 0;
  short new_msg_count = 0;

  char *mailbox = imap_next_word(s);

  /* We need a real tokenizer. */
  if (imap_get_literal_count(mailbox, &litlen) == 0)
  {
    if (imap_cmd_step(idata) != IMAP_CMD_CONTINUE)
    {
      idata->status = IMAP_FATAL;
      return;
    }
    mailbox = idata->buf;
    s = mailbox + litlen;
    *s = '\0';
    s++;
    SKIPWS(s);
  }
  else
  {
    s = imap_next_word(mailbox);
    *(s - 1) = '\0';
    imap_unmunge_mbox_name(idata, mailbox);
  }

  status = imap_mboxcache_get(idata, mailbox, 1);
  olduv = status->uidvalidity;
  oldun = status->uidnext;

  if (*s++ != '(')
  {
    mutt_debug(1, "Error parsing STATUS\n");
    return;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -635,6 +635,13 @@
       idata->status = IMAP_FATAL;
       return;
     }
+
+    if (strlen(idata->buf) < litlen)
+    {
+      mutt_debug(1, "Error parsing STATUS mailbox\n");
+      return;
+    }
+
     mailbox = idata->buf;
     s = mailbox + litlen;
     *s = '\0';
```
