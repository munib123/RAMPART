# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 410_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `410_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 2044-2084 of the vulnerable file.

	 PerlMemShared_malloc(len_wanted) :
	 PerlMemShared_realloc(buffer, len_wanted));
    buffer[0] = size;
    Copy(bits, (buffer + 1), size, char);
    if (size < WARNsize)
	Zero((char *)(buffer + 1) + size, WARNsize - size, char);
    return buffer;
}

/* since we've already done strlen() for both nam and val
 * we can use that info to make things faster than
 * sprintf(s, "%s=%s", nam, val)
 */
#define my_setenv_format(s, nam, nlen, val, vlen) \
   Copy(nam, s, nlen, char); \
   *(s+nlen) = '='; \
   Copy(val, s+(nlen+1), vlen, char); \
   *(s+(nlen+1+vlen)) = '\0'

#ifdef USE_ENVIRON_ARRAY
       /* VMS' my_setenv() is in vms.c */
#if !defined(WIN32) && !defined(NETWARE)
void
Perl_my_setenv(pTHX_ const char *nam, const char *val)
{
  dVAR;
#ifdef __amigaos4__
  amigaos4_obtain_environ(__FUNCTION__);
#endif
#ifdef USE_ITHREADS
  /* only parent thread can modify process environment */
  if (PL_curinterp == aTHX)
#endif
  {
#ifndef PERL_USE_SAFE_PUTENV
    if (!PL_use_safe_putenv) {
        /* most putenv()s leak, so we manipulate environ directly */
        I32 i;
        const I32 len = strlen(nam);
        int nlen, vlen;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2061,8 +2061,40 @@
    *(s+(nlen+1+vlen)) = '\0'
 
 #ifdef USE_ENVIRON_ARRAY
-       /* VMS' my_setenv() is in vms.c */
+
+/* small wrapper for use by Perl_my_setenv that mallocs, or reallocs if
+ * 'current' is non-null, with up to three sizes that are added together.
+ * It handles integer overflow.
+ */
+static char *
+S_env_alloc(void *current, Size_t l1, Size_t l2, Size_t l3, Size_t size)
+{
+    void *p;
+    Size_t sl, l = l1 + l2;
+
+    if (l < l2)
+        goto panic;
+    l += l3;
+    if (l < l3)
+        goto panic;
+    sl = l * size;
+    if (sl < l)
+        goto panic;
+
+    p = current
+            ? safesysrealloc(current, sl)
+            : safesysmalloc(sl);
+    if (p)
+        return (char*)p;
+
+  panic:
+    croak_memory_wrap();
+}
+
+
+/* VMS' my_setenv() is in vms.c */
 #if !defined(WIN32) && !defined(NETWARE)
+
 void
 Perl_my_setenv(pTHX_ const char *nam, const char *val)
 {
@@ -2078,28 +2110,27 @@
 #ifndef PERL_USE_SAFE_PUTENV
     if (!PL_use_safe_putenv) {
         /* most putenv()s leak, so we manipulate environ directly */
-        I32 i;
-        const I32 len = strlen(nam);
-        int nlen, vlen;
+        UV i;
+        Size_t vlen, nlen = strlen(nam);
 
         /* where does it go? */
         for (i = 0; environ[i]; i++) {
-            if (strnEQ(environ[i],nam,len) && environ[i][len] == '=')
+            if (strnEQ(environ[i], nam, nlen) && environ[i][nlen] == '=')
                 break;
         }
 
         if (environ == PL_origenviron) {   /* need we copy environment? */
-            I32 j;
-            I32 max;
+            UV j, max;
             char **tmpenv;
 
             max = i;
             while (environ[max])
                 max++;
-            tmpenv = (char**)safesysmalloc((max+2) * sizeof(char*));
+            /* XXX shouldn't that be max+1 rather than max+2 ??? - DAPM */
+            tmpenv = (char**)S_env_alloc(NULL, max, 2, 0, sizeof(char*));
             for (j=0; j<max; j++) {         /* copy environment */
-                const int len = strlen(environ[j]);
-                tmpenv[j] = (char*)safesysmalloc((len+1)*sizeof(char));
+                const Size_t len = strlen(environ[j]);
+                tmpenv[j] = S_env_alloc(NULL, len, 1, 0, 1);
                 Copy(environ[j], tmpenv[j], len+1, char);
             }
             tmpenv[max] = NULL;
@@ -2118,15 +2149,15 @@
 #endif
         }
         if (!environ[i]) {                 /* does not exist yet */
-            environ = (char**)safesysrealloc(environ, (i+2) * sizeof(char*));
+            environ = (char**)S_env_alloc(environ, i, 2, 0, sizeof(char*));
             environ[i+1] = NULL;    /* make sure it's null terminated */
         }
         else
             safesysfree(environ[i]);
-        nlen = strlen(nam);
+
         vlen = strlen(val);
 
-        environ[i] = (char*)safesysmalloc((nlen+vlen+2) * sizeof(char));
+        environ[i] = S_env_alloc(NULL, nlen, vlen, 2, 1);
         /* all that work just for this */
         my_setenv_format(environ[i], nam, nlen, val, vlen);
     } else {
@@ -2150,22 +2181,21 @@
             if (environ) /* old glibc can crash with null environ */
                 (void)unsetenv(nam);
         } else {
-	    const int nlen = strlen(nam);
-	    const int vlen = strlen(val);
-	    char * const new_env =
-                (char*)safesysmalloc((nlen + vlen + 2) * sizeof(char));
+	    const Size_t nlen = strlen(nam);
+	    const Size_t vlen = strlen(val);
+	    char * const new_env = S_env_alloc(NULL, nlen, vlen, 2, 1);
             my_setenv_format(new_env, nam, nlen, val, vlen);
             (void)putenv(new_env);
         }
 #   else /* ! HAS_UNSETENV */
         char *new_env;
-	const int nlen = strlen(nam);
-	int vlen;
+	const Size_t nlen = strlen(nam);
+	Size_t vlen;
         if (!val) {
 	   val = "";
         }
         vlen = strlen(val);
-        new_env = (char*)safesysmalloc((nlen + vlen + 2) * sizeof(char));
+        new_env = S_env_alloc(NULL, nlen, vlen, 2, 1);
         /* all that work just for this */
         my_setenv_format(new_env, nam, nlen, val, vlen);
         (void)putenv(new_env);
@@ -2187,14 +2217,14 @@
 {
     dVAR;
     char *envstr;
-    const int nlen = strlen(nam);
-    int vlen;
+    const Size_t nlen = strlen(nam);
+    Size_t vlen;
 
     if (!val) {
        val = "";
     }
     vlen = strlen(val);
-    Newx(envstr, nlen+vlen+2, char);
+    envstr = S_env_alloc(NULL, nlen, vlen, 2, 1);
     my_setenv_format(envstr, nam, nlen, val, vlen);
     (void)PerlEnv_putenv(envstr);
     Safefree(envstr);
```
