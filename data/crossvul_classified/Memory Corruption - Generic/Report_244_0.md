# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 244_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `244_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 313-353 of the vulnerable file.

    else if (mutt_str_strncasecmp("UID", s, 3) == 0)
    {
      s += 3;
      SKIPWS(s);
      if (mutt_str_atoui(s, &h->data->uid) < 0)
        return -1;

      s = imap_next_word(s);
    }
    else if (mutt_str_strncasecmp("INTERNALDATE", s, 12) == 0)
    {
      s += 12;
      SKIPWS(s);
      if (*s != '\"')
      {
        mutt_debug(1, "bogus INTERNALDATE entry: %s\n", s);
        return -1;
      }
      s++;
      ptmp = tmp;
      while (*s && *s != '\"')
        *ptmp++ = *s++;
      if (*s != '\"')
        return -1;
      s++; /* skip past the trailing " */
      *ptmp = '\0';
      h->received = mutt_date_parse_imap(tmp);
    }
    else if (mutt_str_strncasecmp("RFC822.SIZE", s, 11) == 0)
    {
      s += 11;
      SKIPWS(s);
      ptmp = tmp;
      while (isdigit((unsigned char) *s))
        *ptmp++ = *s++;
      *ptmp = '\0';
      if (mutt_str_atol(tmp, &h->content_length) < 0)
        return -1;
    }
    else if ((mutt_str_strncasecmp("BODY", s, 4) == 0) ||
             (mutt_str_strncasecmp("RFC822.HEADER", s, 13) == 0))
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -330,7 +330,7 @@
       }
       s++;
       ptmp = tmp;
-      while (*s && *s != '\"')
+      while (*s && (*s != '\"') && (ptmp != (tmp + sizeof(tmp) - 1)))
         *ptmp++ = *s++;
       if (*s != '\"')
         return -1;
@@ -343,7 +343,7 @@
       s += 11;
       SKIPWS(s);
       ptmp = tmp;
-      while (isdigit((unsigned char) *s))
+      while (isdigit((unsigned char) *s) && (ptmp != (tmp + sizeof(tmp) - 1)))
         *ptmp++ = *s++;
       *ptmp = '\0';
       if (mutt_str_atol(tmp, &h->content_length) < 0)
```
