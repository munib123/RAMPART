# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in c
**Pair ID:** 433_0
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `433_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```c
Lines 43-79 of the vulnerable file.

    return pbuf;
}

/* Returns a url-decoded version of str */
/* IMPORTANT: be sure to free() the returned string after use */
char *url_decode(char *str) {
    size_t size = strlen(str) + 1;

    char *buf = mallocz(size);
    return url_decode_r(buf, str, size);
}

char *url_decode_r(char *to, char *url, size_t size) {
    char *s = url,           // source
         *d = to,            // destination
         *e = &to[size - 1]; // destination end

    while(*s && d < e) {
        if(unlikely(*s == '%')) {
            if(likely(s[1] && s[2])) {
                *d++ = from_hex(s[1]) << 4 | from_hex(s[2]);
                s += 2;
            }
        }
        else if(unlikely(*s == '+'))
            *d++ = ' ';

        else
            *d++ = *s;

        s++;
    }

    *d = '\0';

    return to;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -60,7 +60,9 @@
     while(*s && d < e) {
         if(unlikely(*s == '%')) {
             if(likely(s[1] && s[2])) {
-                *d++ = from_hex(s[1]) << 4 | from_hex(s[2]);
+                char t = from_hex(s[1]) << 4 | from_hex(s[2]);
+                // avoid HTTP header injection
+                *d++ = (char)((isprint(t))? t : ' ');
                 s += 2;
             }
         }
```
