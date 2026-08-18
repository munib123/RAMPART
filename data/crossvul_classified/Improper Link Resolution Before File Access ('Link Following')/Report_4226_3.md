# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in c
**Pair ID:** 4226_3
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4226_3`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```c
Lines 2703-2743 of the vulnerable file.

 */
void
netsnmp_init_mib(void)
{
    const char     *prefix;
    char           *env_var, *entry;
    PrefixListPtr   pp = &mib_prefixes[0];
    char           *st = NULL;

    if (Mib)
        return;
    netsnmp_init_mib_internals();

    /*
     * Initialise the MIB directory/ies 
     */
    netsnmp_fixup_mib_directory();
    env_var = strdup(netsnmp_get_mib_directory());
    if (!env_var)
        return;
    netsnmp_mibindex_load();

    DEBUGMSGTL(("init_mib",
                "Seen MIBDIRS: Looking in '%s' for mib dirs ...\n",
                env_var));

    entry = strtok_r(env_var, ENV_SEPARATOR, &st);
    while (entry) {
        add_mibdir(entry);
        entry = strtok_r(NULL, ENV_SEPARATOR, &st);
    }
    SNMP_FREE(env_var);

    env_var = netsnmp_getenv("MIBFILES");
    if (env_var != NULL) {
        if (*env_var == '+')
            entry = strtok_r(env_var+1, ENV_SEPARATOR, &st);
        else
            entry = strtok_r(env_var, ENV_SEPARATOR, &st);
        while (entry) {
            add_mibfile(entry, NULL, NULL);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2720,7 +2720,6 @@
     env_var = strdup(netsnmp_get_mib_directory());
     if (!env_var)
         return;
-    netsnmp_mibindex_load();
 
     DEBUGMSGTL(("init_mib",
                 "Seen MIBDIRS: Looking in '%s' for mib dirs ...\n",
@@ -2740,7 +2739,7 @@
         else
             entry = strtok_r(env_var, ENV_SEPARATOR, &st);
         while (entry) {
-            add_mibfile(entry, NULL, NULL);
+            add_mibfile(entry, NULL);
             entry = strtok_r(NULL, ENV_SEPARATOR, &st);
         }
     }
@@ -2891,142 +2890,6 @@
 #endif
 
 
-/*
- * Handle MIB indexes centrally
- */
-static int _mibindex     = 0;   /* Last index in use */
-static int _mibindex_max = 0;   /* Size of index array */
-char     **_mibindexes   = NULL;
-
-int _mibindex_add( const char *dirname, int i );
-void
-netsnmp_mibindex_load( void )
-{
-    DIR *dir;
-    struct dirent *file;
-    FILE *fp;
-    char tmpbuf[ 300];
-    char tmpbuf2[300];
-    int  i;
-    char *cp;
-
-    /*
-     * Open the MIB index directory, or create it (empty)
-     */
-    snprintf( tmpbuf, sizeof(tmpbuf), "%s/mib_indexes",
-              get_persistent_directory());
-    tmpbuf[sizeof(tmpbuf)-1] = 0;
-    dir = opendir( tmpbuf );
-    if ( dir == NULL ) {
-        DEBUGMSGTL(("mibindex", "load: (new)\n"));
-        mkdirhier( tmpbuf, NETSNMP_AGENT_DIRECTORY_MODE, 0);
-        return;
-    }
-
-    /*
-     * Create a list of which directory each file refers to
-     */
-    while ((file = readdir( dir ))) {
-        if ( !isdigit((unsigned char)(file->d_name[0])))
-            continue;
-        i = atoi( file->d_name );
-
-        snprintf( tmpbuf, sizeof(tmpbuf), "%s/mib_indexes/%d",
-              get_persistent_directory(), i );
-        tmpbuf[sizeof(tmpbuf)-1] = 0;
-        fp = fopen( tmpbuf, "r" );
-        if (!fp)
-            continue;
-        cp = fgets( tmpbuf2, sizeof(tmpbuf2), fp );
-        fclose( fp );
-        if ( !cp ) {
-            DEBUGMSGTL(("mibindex", "Empty MIB index (%d)\n", i));
-            continue;
-        }
-        if ( strncmp( tmpbuf2, "DIR ", 4 ) != 0 ) {
-            DEBUGMSGTL(("mibindex", "Malformed MIB index (%d)\n", i));
-            continue;
-        }
-        tmpbuf2[strlen(tmpbuf2)-1] = 0;
-        DEBUGMSGTL(("mibindex", "load: (%d) %s\n", i, tmpbuf2));
-        (void)_mibindex_add( tmpbuf2+4, i );  /* Skip 'DIR ' */
-    }
-    closedir( dir );
-}
-
-char *
-netsnmp_mibindex_lookup( const char *dirname )
-{
-    int i;
-    static char tmpbuf[300];
-
-    for (i=0; i<_mibindex; i++) {
-        if ( _mibindexes[i] &&
-             strcmp( _mibindexes[i], dirname ) == 0) {
-             snprintf(tmpbuf, sizeof(tmpbuf), "%s/mib_indexes/%d",
-                      get_persistent_directory(), i);
-             tmpbuf[sizeof(tmpbuf)-1] = 0;
-             DEBUGMSGTL(("mibindex", "lookup: %s (%d) %s\n", dirname, i, tmpbuf ));
-             return tmpbuf;
-        }
-    }
-    DEBUGMSGTL(("mibindex", "lookup: (none)\n"));
-    return NULL;
-}
-
-int
-_mibindex_add( const char *dirname, int i )
-{
-    const int old_mibindex_max = _mibindex_max;
-
-    DEBUGMSGTL(("mibindex", "add: %s (%d)\n", dirname, i ));
-    if ( i == -1 )
-        i = _mibindex++;
-    if ( i >= _mibindex_max ) {
-        /*
-         * If the index array is full (or non-existent)
-         *   then expand (or create) it
-         */
-        _mibindex_max = i + 10;
-        _mibindexes = realloc(_mibindexes,
-                              _mibindex_max * sizeof(_mibindexes[0]));
-        netsnmp_assert(_mibindexes);
-        memset(_mibindexes + old_mibindex_max, 0,
-               (_mibindex_max - old_mibindex_max) * sizeof(_mibindexes[0]));
-    }
-
-    _mibindexes[ i ] = strdup( dirname );
-    if ( i >= _mibindex )
-        _mibindex = i+1;
-
-    DEBUGMSGTL(("mibindex", "add: %d/%d/%d\n", i, _mibindex, _mibindex_max ));
-    return i;
-}
-    
-FILE *
-netsnmp_mibindex_new( const char *dirname )
-{
-    FILE *fp;
-    char  tmpbuf[300];
-    char *cp;
-    int   i;
-
-    cp = netsnmp_mibindex_lookup( dirname );
-    if (!cp) {
-        i  = _mibindex_add( dirname, -1 );
-        snprintf( tmpbuf, sizeof(tmpbuf), "%s/mib_indexes/%d",
-                  get_persistent_directory(), i );
-        tmpbuf[sizeof(tmpbuf)-1] = 0;
-        cp = tmpbuf;
-    }
-    DEBUGMSGTL(("mibindex", "new: %s (%s)\n", dirname, cp ));
-    fp = fopen( cp, "w" );
-    if (fp)
-        fprintf( fp, "DIR %s\n", dirname );
-    return fp;
-}
-
-
 /**
  * Unloads all mibs.
  */
@@ -3041,15 +2904,6 @@
     }
     tree_head = NULL;
     Mib = NULL;
-    if (_mibindexes) {
-        int i;
-        for (i = 0; i < _mibindex; ++i)
-            SNMP_FREE(_mibindexes[i]);
-        free(_mibindexes);
-        _mibindex = 0;
-        _mibindex_max = 0;
-        _mibindexes = NULL;
-    }
     if (Prefix != NULL && Prefix != &Standard_Prefix[0])
         SNMP_FREE(Prefix);
     if (Prefix)
```
