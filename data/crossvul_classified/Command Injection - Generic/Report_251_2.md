# CrossVul Fix Pair: Improper Neutralization of Special Elements used in a Command ('Command Injection') in c
**Pair ID:** 251_2
**Vulnerability Class:** Command Injection - Generic
**CWE:** CWE-77
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `251_2`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in a Command ('Command Injection') - Command injection vulnerabilities typically occur when: 1.

## Vulnerable Code
```c
Lines 447-487 of the vulnerable file.

    }
  }
  else
  {
    char term[STRING];
    char *delim = NULL;

    switch (pat->op)
    {
      case MUTT_HEADER:
        mutt_buffer_addstr(buf, "HEADER ");

        /* extract header name */
        delim = strchr(pat->p.str, ':');
        if (!delim)
        {
          mutt_error(_("Header search without header name: %s"), pat->p.str);
          return -1;
        }
        *delim = '\0';
        imap_quote_string(term, sizeof(term), pat->p.str);
        mutt_buffer_addstr(buf, term);
        mutt_buffer_addch(buf, ' ');

        /* and field */
        *delim = ':';
        delim++;
        SKIPWS(delim);
        imap_quote_string(term, sizeof(term), delim);
        mutt_buffer_addstr(buf, term);
        break;
      case MUTT_BODY:
        mutt_buffer_addstr(buf, "BODY ");
        imap_quote_string(term, sizeof(term), pat->p.str);
        mutt_buffer_addstr(buf, term);
        break;
      case MUTT_WHOLE_MSG:
        mutt_buffer_addstr(buf, "TEXT ");
        imap_quote_string(term, sizeof(term), pat->p.str);
        mutt_buffer_addstr(buf, term);
        break;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -464,7 +464,7 @@
           return -1;
         }
         *delim = '\0';
-        imap_quote_string(term, sizeof(term), pat->p.str);
+        imap_quote_string(term, sizeof(term), pat->p.str, false);
         mutt_buffer_addstr(buf, term);
         mutt_buffer_addch(buf, ' ');
 
@@ -472,17 +472,17 @@
         *delim = ':';
         delim++;
         SKIPWS(delim);
-        imap_quote_string(term, sizeof(term), delim);
+        imap_quote_string(term, sizeof(term), delim, false);
         mutt_buffer_addstr(buf, term);
         break;
       case MUTT_BODY:
         mutt_buffer_addstr(buf, "BODY ");
-        imap_quote_string(term, sizeof(term), pat->p.str);
+        imap_quote_string(term, sizeof(term), pat->p.str, false);
         mutt_buffer_addstr(buf, term);
         break;
       case MUTT_WHOLE_MSG:
         mutt_buffer_addstr(buf, "TEXT ");
-        imap_quote_string(term, sizeof(term), pat->p.str);
+        imap_quote_string(term, sizeof(term), pat->p.str, false);
         mutt_buffer_addstr(buf, term);
         break;
       case MUTT_SERVERSEARCH:
@@ -495,7 +495,7 @@
         }
       }
         mutt_buffer_addstr(buf, "X-GM-RAW ");
-        imap_quote_string(term, sizeof(term), pat->p.str);
+        imap_quote_string(term, sizeof(term), pat->p.str, false);
         mutt_buffer_addstr(buf, term);
         break;
     }
```
