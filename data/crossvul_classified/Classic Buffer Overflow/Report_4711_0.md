# CrossVul Fix Pair: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') in c
**Pair ID:** 4711_0
**Vulnerability Class:** Classic Buffer Overflow
**CWE:** CWE-120
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4711_0`)

## Vulnerability Information & PoC

## Description
Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') - A buffer overflow condition exists when a product attempts to put more data in a buffer than it can hold, or when it attempts to put data in a memory area outside of the boundaries of a buffer.

## Vulnerable Code
```c
Lines 55-97 of the vulnerable file.


   DEBUG_MSG("gtkui_conf_get: name=%s", name);

   for(c = 0; settings[c].name != NULL; c++) {
      if(!strcmp(name, settings[c].name))
          return(settings[c].value);
   }

   return(0);
}

void gtkui_conf_read(void) {
   FILE *fd;
   const char *path;
   char line[100], name[30];
   short value;

#ifdef OS_WINDOWS
   path = ec_win_get_user_dir();
#else
   /* TODO: get the dopped privs home dir instead of "/root" */
   /* path = g_get_home_dir(); */
   path = g_get_tmp_dir();
#endif

   filename = g_build_filename(path, ".ettercap_gtk", NULL);

   DEBUG_MSG("gtkui_conf_read: %s", filename);

   fd = fopen(filename, "r");
   if(!fd) 
      return;

   while(fgets(line, 100, fd)) {
      sscanf(line, "%s = %hd", name, &value);

      gtkui_conf_set(name, value);
   }
   fclose(fd);
}

void gtkui_conf_save(void) {
   FILE *fd;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -72,9 +72,7 @@
 #ifdef OS_WINDOWS
    path = ec_win_get_user_dir();
 #else
-   /* TODO: get the dopped privs home dir instead of "/root" */
-   /* path = g_get_home_dir(); */
-   path = g_get_tmp_dir();
+   path = g_get_home_dir();
 #endif
 
    filename = g_build_filename(path, ".ettercap_gtk", NULL);
```
