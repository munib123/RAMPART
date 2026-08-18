# CrossVul Fix Pair: Improper Neutralization of Special Elements used in a Command ('Command Injection') in c
**Pair ID:** 251_4
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-77
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `251_4`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in a Command ('Command Injection') - Command injection vulnerabilities typically occur when: 1.

## Vulnerable Code
```c
Lines 781-821 of the vulnerable file.

 * given ImapMbox and relative path.
 */
void imap_qualify_path(char *dest, size_t len, struct ImapMbox *mx, char *path)
{
  struct Url url;

  mutt_account_tourl(&mx->account, &url);
  url.path = path;

  url_tostring(&url, dest, len, 0);
}

/**
 * imap_quote_string - quote string according to IMAP rules
 * @param dest Buffer for the result
 * @param dlen Length of the buffer
 * @param src  String to be quoted
 *
 * Surround string with quotes, escape " and \ with backslash
 */
void imap_quote_string(char *dest, size_t dlen, const char *src)
{
  static const char quote[] = "\"\\";
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
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -798,9 +798,12 @@
  *
  * Surround string with quotes, escape " and \ with backslash
  */
-void imap_quote_string(char *dest, size_t dlen, const char *src)
-{
-  static const char quote[] = "\"\\";
+void imap_quote_string(char *dest, size_t dlen, const char *src, bool quote_backtick)
+{
+  const char *quote = "`\"\\";
+  if (!quote_backtick)
+    quote++;
+
   char *pt = dest;
   const char *s = src;
 
@@ -874,7 +877,7 @@
   char *buf = mutt_str_strdup(src);
   imap_utf_encode(idata, &buf);
 
-  imap_quote_string(dest, dlen, buf);
+  imap_quote_string(dest, dlen, buf, false);
 
   FREE(&buf);
 }
```
