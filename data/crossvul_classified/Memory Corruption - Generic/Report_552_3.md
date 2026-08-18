# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 552_3
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `552_3`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 175-216 of the vulnerable file.

    print_remote_ip (req, stdout);
    printf(" - - %s\"%s\" %d %zu \"%s\" \"%s\"\n",
           get_commonlog_time(),
           req->logline ? req->logline : "-",
           req->response_status,
           req->bytes_written,
           (req->header_referer ? req->header_referer : "-"),
           (req->header_user_agent ? req->header_user_agent : "-"));
}

static char *escape_pathname(const char *inp)
{
    const unsigned char *s;
    char *escaped, *d;

    if (!inp) {
        return NULL;
    }
    escaped = malloc (4 * strlen(inp) + 1);
    if (!escaped) {
    	perror("malloc");
	return NULL;
    }
    for (d = escaped, s = (const unsigned char *)inp; *s; s++) {
        if (needs_escape (*s)) {
            snprintf (d, 5, "\\x%02x", *s);
            d += strlen (d);
        } else {
            *d++ = *s;
        }
    }
    *d++ = '\0';
    return escaped;
}

/*
 * Name: log_error_doc
 *
 * Description: Logs the current time and transaction identification
 * to the stderr (the error log):
 * should always be followed by an fprintf to stderr
 *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -192,8 +192,8 @@
     }
     escaped = malloc (4 * strlen(inp) + 1);
     if (!escaped) {
-    	perror("malloc");
-	return NULL;
+		perror("malloc");
+		return NULL;
     }
     for (d = escaped, s = (const unsigned char *)inp; *s; s++) {
         if (needs_escape (*s)) {
```
