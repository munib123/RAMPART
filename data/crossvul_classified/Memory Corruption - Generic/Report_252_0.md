# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 252_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `252_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 117-157 of the vulnerable file.

    return IMAP_AUTH_FAILURE;

  imap_cmd_start(idata, "AUTHENTICATE CRAM-MD5");

  /* From RFC2195:
   * The data encoded in the first ready response contains a presumptively
   * arbitrary string of random digits, a timestamp, and the fully-qualified
   * primary host name of the server. The syntax of the unencoded form must
   * correspond to that of an RFC822 'msg-id' [RFC822] as described in [POP3].
   */
  do
    rc = imap_cmd_step(idata);
  while (rc == IMAP_CMD_CONTINUE);

  if (rc != IMAP_CMD_RESPOND)
  {
    mutt_debug(1, "Invalid response from server: %s\n", ibuf);
    goto bail;
  }

  len = mutt_b64_decode(obuf, idata->buf + 2);
  if (len == -1)
  {
    mutt_debug(1, "Error decoding base64 response.\n");
    goto bail;
  }

  obuf[len] = '\0';
  mutt_debug(2, "CRAM challenge: %s\n", obuf);

  /* The client makes note of the data and then responds with a string
   * consisting of the user name, a space, and a 'digest'. The latter is
   * computed by applying the keyed MD5 algorithm from [KEYED-MD5] where the
   * key is a shared secret and the digested text is the timestamp (including
   * angle-brackets).
   *
   * Note: The user name shouldn't be quoted. Since the digest can't contain
   *   spaces, there is no ambiguity. Some servers get this wrong, we'll work
   *   around them when the bug report comes in. Until then, we'll remain
   *   blissfully RFC-compliant.
   */
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -134,7 +134,7 @@
     goto bail;
   }
 
-  len = mutt_b64_decode(obuf, idata->buf + 2);
+  len = mutt_b64_decode(obuf, idata->buf + 2, sizeof(obuf));
   if (len == -1)
   {
     mutt_debug(1, "Error decoding base64 response.\n");
```
