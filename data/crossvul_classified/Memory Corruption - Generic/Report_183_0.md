# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 183_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `183_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 135-175 of the vulnerable file.


/*------------------------------------------------------------------------------
 * Utility functions
 *--------------------------------------------------------------------------- */

static long long ustime(void) {
    struct timeval tv;
    long long ust;

    gettimeofday(&tv, NULL);
    ust = ((long long)tv.tv_sec)*1000000;
    ust += tv.tv_usec;
    return ust;
}

static long long mstime(void) {
    return ustime()/1000;
}

static void cliRefreshPrompt(void) {
    int len;

    if (config.eval_ldb) return;
    if (config.hostsocket != NULL)
        len = snprintf(config.prompt,sizeof(config.prompt),"redis %s",
                       config.hostsocket);
    else
        len = anetFormatAddr(config.prompt, sizeof(config.prompt),
                           config.hostip, config.hostport);
    /* Add [dbnum] if needed */
    if (config.dbnum != 0)
        len += snprintf(config.prompt+len,sizeof(config.prompt)-len,"[%d]",
            config.dbnum);
    snprintf(config.prompt+len,sizeof(config.prompt)-len,"> ");
}

/* Return the name of the dotfile for the specified 'dotfilename'.
 * Normally it just concatenates user $HOME to the file specified
 * in 'dotfilename'. However if the environment varialbe 'envoverride'
 * is set, its value is taken as the path.
 *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -152,20 +152,25 @@
 }
 
 static void cliRefreshPrompt(void) {
-    int len;
-
     if (config.eval_ldb) return;
-    if (config.hostsocket != NULL)
-        len = snprintf(config.prompt,sizeof(config.prompt),"redis %s",
-                       config.hostsocket);
-    else
-        len = anetFormatAddr(config.prompt, sizeof(config.prompt),
-                           config.hostip, config.hostport);
+
+    sds prompt = sdsempty();
+    if (config.hostsocket != NULL) {
+        prompt = sdscatfmt(prompt,"redis %s",config.hostsocket);
+    } else {
+        char addr[256];
+        anetFormatAddr(addr, sizeof(addr), config.hostip, config.hostport);
+        prompt = sdscatlen(prompt,addr,strlen(addr));
+    }
+
     /* Add [dbnum] if needed */
     if (config.dbnum != 0)
-        len += snprintf(config.prompt+len,sizeof(config.prompt)-len,"[%d]",
-            config.dbnum);
-    snprintf(config.prompt+len,sizeof(config.prompt)-len,"> ");
+        prompt = sdscatfmt(prompt,"[%i]",config.dbnum);
+
+    /* Copy the prompt in the static buffer. */
+    prompt = sdscatlen(prompt,"> ",2);
+    snprintf(config.prompt,sizeof(config.prompt),"%s",prompt);
+    sdsfree(prompt);
 }
 
 /* Return the name of the dotfile for the specified 'dotfilename'.
```
