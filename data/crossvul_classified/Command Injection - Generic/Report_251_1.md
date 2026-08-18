# CrossVul Fix Pair: Improper Neutralization of Special Elements used in a Command ('Command Injection') in c
**Pair ID:** 251_1
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-77
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `251_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in a Command ('Command Injection') - Command injection vulnerabilities typically occur when: 1.

## Vulnerable Code
```c
Lines 482-522 of the vulnerable file.

    cmd_parse_list(idata, s);
    return;
  }

  if (!ImapCheckSubscribed)
    return;

  idata->cmdtype = IMAP_CT_LIST;
  idata->cmddata = &list;
  cmd_parse_list(idata, s);
  idata->cmddata = NULL;
  /* noselect is for a gmail quirk (#3445) */
  if (!list.name || list.noselect)
    return;

  mutt_debug(3, "Subscribing to %s\n", list.name);

  mutt_str_strfcpy(buf, "mailboxes \"", sizeof(buf));
  mutt_account_tourl(&idata->conn->account, &url);
  /* escape \ and " */
  imap_quote_string(errstr, sizeof(errstr), list.name);
  url.path = errstr + 1;
  url.path[strlen(url.path) - 1] = '\0';
  if (mutt_str_strcmp(url.user, ImapUser) == 0)
    url.user = NULL;
  url_tostring(&url, buf + 11, sizeof(buf) - 11, 0);
  mutt_str_strcat(buf, sizeof(buf), "\"");
  mutt_buffer_init(&token);
  mutt_buffer_init(&err);
  err.data = errstr;
  err.dsize = sizeof(errstr);
  if (mutt_parse_rc_line(buf, &token, &err))
    mutt_debug(1, "Error adding subscribed mailbox: %s\n", errstr);
  FREE(&token.data);
}

/**
 * cmd_parse_myrights - Set rights bits according to MYRIGHTS response
 * @param idata Server data
 * @param s     Command string with rights info
 */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -499,7 +499,7 @@
   mutt_str_strfcpy(buf, "mailboxes \"", sizeof(buf));
   mutt_account_tourl(&idata->conn->account, &url);
   /* escape \ and " */
-  imap_quote_string(errstr, sizeof(errstr), list.name);
+  imap_quote_string(errstr, sizeof(errstr), list.name, true);
   url.path = errstr + 1;
   url.path[strlen(url.path) - 1] = '\0';
   if (mutt_str_strcmp(url.user, ImapUser) == 0)
```
