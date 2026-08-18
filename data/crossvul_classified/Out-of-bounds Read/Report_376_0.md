# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 376_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `376_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 50-90 of the vulnerable file.

    len = strlen(print_buffer);

    ptr = print_buffer;
    while(len > 0) {
      fputs(prefix, config->errors);

      if(len > width) {
        size_t cut = width-1;

        while(!ISSPACE(ptr[cut]) && cut) {
          cut--;
        }
        if(0 == cut)
          /* not a single cutting position was found, just cut it at the
             max text width then! */
          cut = width-1;

        (void)fwrite(ptr, cut + 1, 1, config->errors);
        fputs("\n", config->errors);
        ptr += cut + 1; /* skip the space too */
        len -= cut;
      }
      else {
        fputs(ptr, config->errors);
        len = 0;
      }
    }
    curl_free(print_buffer);
  }
}

/*
 * Emit 'note' formatted message on configured 'errors' stream, if verbose was
 * selected.
 */
void notef(struct GlobalConfig *config, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  if(config->tracetype)
    voutf(config, NOTE_PREFIX, fmt, ap);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -67,7 +67,7 @@
         (void)fwrite(ptr, cut + 1, 1, config->errors);
         fputs("\n", config->errors);
         ptr += cut + 1; /* skip the space too */
-        len -= cut;
+        len -= cut + 1;
       }
       else {
         fputs(ptr, config->errors);
```
