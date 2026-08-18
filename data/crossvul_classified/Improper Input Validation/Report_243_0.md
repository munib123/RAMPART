# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 243_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `243_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 875-915 of the vulnerable file.

  {
    mutt_debug(2, "Handling BYE\n");

    /* check if we're logging out */
    if (idata->status == IMAP_BYE)
      return 0;

    /* server shut down our connection */
    s += 3;
    SKIPWS(s);
    mutt_error("%s", s);
    cmd_handle_fatal(idata);

    return -1;
  }
  else if (ImapServernoise && (mutt_str_strncasecmp("NO", s, 2) == 0))
  {
    mutt_debug(2, "Handling untagged NO\n");

    /* Display the warning message from the server */
    mutt_error("%s", s + 3);
  }

  return 0;
}

/**
 * imap_cmd_start - Given an IMAP command, send it to the server
 * @param idata  Server data
 * @param cmdstr Command string to send
 * @retval  0 Success
 * @retval <0 Failure, e.g. #IMAP_CMD_BAD
 *
 * If cmdstr is NULL, sends queued commands.
 */
int imap_cmd_start(struct ImapData *idata, const char *cmdstr)
{
  return cmd_start(idata, cmdstr, 0);
}

/**
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -892,7 +892,7 @@
     mutt_debug(2, "Handling untagged NO\n");
 
     /* Display the warning message from the server */
-    mutt_error("%s", s + 3);
+    mutt_error("%s", s + 2);
   }
 
   return 0;
```
