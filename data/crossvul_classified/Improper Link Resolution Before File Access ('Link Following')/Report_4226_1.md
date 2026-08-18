# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in c
**Pair ID:** 4226_1
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4226_1`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```c
Lines 107-149 of the vulnerable file.

#define MIB_TCPCONNSTATE_LASTACK	9
#define MIB_TCPCONNSTATE_CLOSING	10
#define MIB_TCPCONNSTATE_TIMEWAIT	11

#define MIB_EGPNEIGHSTATE_IDLE		1
#define MIB_EGPNEIGHSTATE_AQUISITION	2
#define MIB_EGPNEIGHSTATE_DOWN		3
#define MIB_EGPNEIGHSTATE_UP		4
#define MIB_EGPNEIGHSTATE_CEASE		5

    struct variable_list;
    struct enum_list;

    NETSNMP_IMPORT
    void            print_ascii_dump(FILE *);
    void            register_mib_handlers(void);
    void            netsnmp_set_mib_directory(const char *dir);
    NETSNMP_IMPORT
    char            *netsnmp_get_mib_directory(void);
    void            netsnmp_fixup_mib_directory(void);
    void            netsnmp_mibindex_load( void );
    char *          netsnmp_mibindex_lookup( const char * );
    FILE *          netsnmp_mibindex_new( const char * );
    int             sprint_realloc_description(u_char ** buf, size_t * buf_len,
                                size_t * out_len, int allow_realloc,
                                oid * objid, size_t objidlen, int width);
    NETSNMP_IMPORT
    int             get_wild_node(const char *, oid *, size_t *);
    NETSNMP_IMPORT
    int             get_node(const char *, oid *, size_t *);
    NETSNMP_IMPORT
    struct tree    *get_tree(const oid *, size_t, struct tree *);
    NETSNMP_IMPORT
    struct tree    *get_tree_head(void);
    void            set_function(struct tree *);

    NETSNMP_IMPORT
    int             parse_one_oid_index(oid ** oidStart, size_t * oidLen,
                                        netsnmp_variable_list * data,
                                        int complete);
    NETSNMP_IMPORT
    int             parse_oid_indexes(oid * oidIndex, size_t oidLen,
                                      netsnmp_variable_list * data);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -124,9 +124,6 @@
     NETSNMP_IMPORT
     char            *netsnmp_get_mib_directory(void);
     void            netsnmp_fixup_mib_directory(void);
-    void            netsnmp_mibindex_load( void );
-    char *          netsnmp_mibindex_lookup( const char * );
-    FILE *          netsnmp_mibindex_new( const char * );
     int             sprint_realloc_description(u_char ** buf, size_t * buf_len,
                                 size_t * out_len, int allow_realloc,
                                 oid * objid, size_t objidlen, int width);
```
