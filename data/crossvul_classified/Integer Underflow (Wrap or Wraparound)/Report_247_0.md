# CrossVul Fix Pair: Integer Underflow (Wrap or Wraparound) in c
**Pair ID:** 247_0
**Vulnerability Class:** Integer Underflow (Wrap or Wraparound)
**CWE:** CWE-191
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `247_0`)

## Vulnerability Information & PoC

## Description
Integer Underflow (Wrap or Wraparound) - This can happen in signed and unsigned cases.

## Vulnerable Code
```c
Lines 804-844 of the vulnerable file.

 *
 * Surround string with quotes, escape " and \ with backslash
 */
void imap_quote_string(char *dest, size_t dlen, const char *src, bool quote_backtick)
{
  const char *quote = "`\"\\";
  if (!quote_backtick)
    quote++;

  char *pt = dest;
  const char *s = src;

  *pt++ = '"';
  /* save room for trailing quote-char */
  dlen -= 2;

  for (; *s && dlen; s++)
  {
    if (strchr(quote, *s))
    {
      dlen -= 2;
      if (dlen == 0)
        break;
      *pt++ = '\\';
      *pt++ = *s;
    }
    else
    {
      *pt++ = *s;
      dlen--;
    }
  }
  *pt++ = '"';
  *pt = '\0';
}

/**
 * imap_unquote_string - equally stupid unquoting routine
 * @param s String to be unquoted
 */
void imap_unquote_string(char *s)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -821,9 +821,9 @@
   {
     if (strchr(quote, *s))
     {
+      if (dlen < 2)
+        break;
       dlen -= 2;
-      if (dlen == 0)
-        break;
       *pt++ = '\\';
       *pt++ = *s;
     }
```
