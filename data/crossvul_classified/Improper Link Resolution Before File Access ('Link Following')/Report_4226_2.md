# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in c
**Pair ID:** 4226_2
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4226_2`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```c
Lines 184-224 of the vulnerable file.

#define	MIB_ACCESS_WRITEONLY   20
#define MIB_ACCESS_NOACCESS    21
#define MIB_ACCESS_NOTIFY      67
#define MIB_ACCESS_CREATE      48

#define MIB_STATUS_MANDATORY   23
#define MIB_STATUS_OPTIONAL    24
#define MIB_STATUS_OBSOLETE    25
#define MIB_STATUS_DEPRECATED  39
#define MIB_STATUS_CURRENT     57

#define	ANON	"anonymous#"
#define	ANON_LEN  strlen(ANON)

    int             netsnmp_unload_module(const char *name);
#ifndef NETSNMP_NO_LEGACY_DEFINITIONS
    int             unload_module(const char *name);
#endif
    void            netsnmp_init_mib_internals(void);
    void            unload_all_mibs(void);
    int             add_mibfile(const char*, const char*, FILE *);
    int             which_module(const char *);
    NETSNMP_IMPORT
    char           *module_name(int, char *);
    NETSNMP_IMPORT
    void            print_subtree(FILE *, struct tree *, int);
    NETSNMP_IMPORT
    void            print_ascii_dump_tree(FILE *, struct tree *, int);
    NETSNMP_IMPORT
    struct tree    *find_tree_node(const char *, int);
    NETSNMP_IMPORT
    const char     *get_tc_descriptor(int);
    NETSNMP_IMPORT
    const char     *get_tc_description(int);
    NETSNMP_IMPORT
    struct tree    *find_best_tree_node(const char *, struct tree *,
                                        u_int *);
    /*
     * backwards compatability 
     */
    NETSNMP_IMPORT
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -201,7 +201,7 @@
 #endif
     void            netsnmp_init_mib_internals(void);
     void            unload_all_mibs(void);
-    int             add_mibfile(const char*, const char*, FILE *);
+    int             add_mibfile(const char*, const char*);
     int             which_module(const char *);
     NETSNMP_IMPORT
     char           *module_name(int, char *);
```
