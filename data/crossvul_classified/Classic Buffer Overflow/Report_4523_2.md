# CrossVul Fix Pair: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') in c
**Pair ID:** 4523_2
**Vulnerability Class:** Classic Buffer Overflow
**CWE:** CWE-120
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4523_2`)

## Vulnerability Information & PoC

## Description
Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') - A buffer overflow condition exists when a product attempts to put more data in a buffer than it can hold, or when it attempts to put data in a memory area outside of the boundaries of a buffer.

## Vulnerable Code
```c
Lines 226-266 of the vulnerable file.

#ifdef WINCHAIN
static struct win_choices *
win_choices_find(s)
const char *s;
{
    register int i;

    for (i = 0; winchoices[i].procs; i++) {
        if (!strcmpi(s, winchoices[i].procs->name)) {
            return &winchoices[i];
        }
    }
    return (struct win_choices *) 0;
}
#endif

void
choose_windows(s)
const char *s;
{
    register int i;

    for (i = 0; winchoices[i].procs; i++) {
        if ('+' == winchoices[i].procs->name[0])
            continue;
        if ('-' == winchoices[i].procs->name[0])
            continue;
        if (!strcmpi(s, winchoices[i].procs->name)) {
            windowprocs = *winchoices[i].procs;

            if (last_winchoice && last_winchoice->ini_routine)
                (*last_winchoice->ini_routine)(WININIT_UNDO);
            if (winchoices[i].ini_routine)
                (*winchoices[i].ini_routine)(WININIT);
            last_winchoice = &winchoices[i];
            return;
        }
    }

    if (!windowprocs.win_raw_print)
        windowprocs.win_raw_print = def_raw_print;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -243,7 +243,8 @@
 choose_windows(s)
 const char *s;
 {
-    register int i;
+    int i;
+    char *tmps = 0;
 
     for (i = 0; winchoices[i].procs; i++) {
         if ('+' == winchoices[i].procs->name[0])
@@ -269,9 +270,22 @@
         windowprocs.win_wait_synch = def_wait_synch;
 
     if (!winchoices[0].procs) {
-        raw_printf("No window types?");
+        raw_printf("No window types supported?");
         nh_terminate(EXIT_FAILURE);
     }
+    /* 50: arbitrary, no real window_type names are anywhere near that long;
+       used to prevent potential raw_printf() overflow if user supplies a
+       very long string (on the order of 1200 chars) on the command line
+       (config file options can't get that big; they're truncated at 1023) */
+#define WINDOW_TYPE_MAXLEN 50
+    if (strlen(s) >= WINDOW_TYPE_MAXLEN) {
+        tmps = (char *) alloc(WINDOW_TYPE_MAXLEN);
+        (void) strncpy(tmps, s, WINDOW_TYPE_MAXLEN - 1);
+        tmps[WINDOW_TYPE_MAXLEN - 1] = '\0';
+        s = tmps;
+    }
+#undef WINDOW_TYPE_MAXLEN
+
     if (!winchoices[1].procs) {
         config_error_add(
                      "Window type %s not recognized.  The only choice is: %s",
@@ -293,6 +307,8 @@
         config_error_add("Window type %s not recognized.  Choices are:  %s",
                          s, buf);
     }
+    if (tmps)
+        free((genericptr_t) tmps) /*, tmps = 0*/ ;
 
     if (windowprocs.win_raw_print == def_raw_print
             || WINDOWPORT("safe-startup"))
```
