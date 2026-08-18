# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in c
**Pair ID:** 4226_4
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4226_4`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```c
Lines 589-630 of the vulnerable file.

static int      get_tc_index(const char *, int);
static struct enum_list *parse_enumlist(FILE *, struct enum_list **);
static struct range_list *parse_ranges(FILE * fp, struct range_list **);
static struct node *parse_asntype(FILE *, char *, int *, char *);
static struct node *parse_objecttype(FILE *, char *);
static struct node *parse_objectgroup(FILE *, char *, int,
                                      struct objgroup **);
static struct node *parse_notificationDefinition(FILE *, char *);
static struct node *parse_trapDefinition(FILE *, char *);
static struct node *parse_compliance(FILE *, char *);
static struct node *parse_capabilities(FILE *, char *);
static struct node *parse_moduleIdentity(FILE *, char *);
static struct node *parse_macro(FILE *, char *);
static void     parse_imports(FILE *);
static struct node *parse(FILE *, struct node *);

static int     read_module_internal(const char *);
static int     read_module_replacements(const char *);
static int     read_import_replacements(const char *,
                                         struct module_import *);

static void     new_module(const char *, const char *);

static struct node *merge_parse_objectid(struct node *, FILE *, char *);
static struct index_list *getIndexes(FILE * fp, struct index_list **);
static struct varbind_list *getVarbinds(FILE * fp, struct varbind_list **);
static void     free_indexes(struct index_list **);
static void     free_varbinds(struct varbind_list **);
static void     free_ranges(struct range_list **);
static void     free_enums(struct enum_list **);
static struct range_list *copy_ranges(struct range_list *);
static struct enum_list *copy_enums(struct enum_list *);

static u_int    compute_match(const char *search_base, const char *key);

void
snmp_mib_toggle_options_usage(const char *lead, FILE * outf)
{
    fprintf(outf, "%su:  %sallow the use of underlines in MIB symbols\n",
            lead, ((netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,
					   NETSNMP_DS_LIB_MIB_PARSE_LABEL)) ?
		   "dis" : ""));
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -607,8 +607,6 @@
 static int     read_import_replacements(const char *,
                                          struct module_import *);
 
-static void     new_module(const char *, const char *);
-
 static struct node *merge_parse_objectid(struct node *, FILE *, char *);
 static struct index_list *getIndexes(FILE * fp, struct index_list **);
 static struct varbind_list *getVarbinds(FILE * fp, struct varbind_list **);
@@ -4859,7 +4857,7 @@
 #endif /* NETSNMP_FEATURE_REMOVE_PARSE_GET_TOKEN */
 
 int
-add_mibfile(const char* tmpstr, const char* d_name, FILE *ip )
+add_mibfile(const char* tmpstr, const char* d_name)
 {
     FILE           *fp;
     char            token[MAXTOKEN], token2[MAXTOKEN];
@@ -4884,8 +4882,6 @@
      */
     if (get_token(fp, token2, MAXTOKEN) == DEFINITIONS) {
         new_module(token, tmpstr);
-        if (ip)
-            fprintf(ip, "%s %s\n", token, d_name);
         fclose(fp);
         return 0;
     } else {
@@ -4977,71 +4973,22 @@
 int
 add_mibdir(const char *dirname)
 {
-    FILE           *ip;
     const char     *oldFile = File;
     char          **filenames;
     int             count = 0;
     int             filename_count, i;
-#if !(defined(WIN32) || defined(cygwin))
-    char           *token;
-    char space;
-    char newline;
-    struct stat     dir_stat, idx_stat;
-    char            tmpstr[300];
-    char            tmpstr1[300];
-#endif
 
     DEBUGMSGTL(("parse-mibs", "Scanning directory %s\n", dirname));
-#if !(defined(WIN32) || defined(cygwin))
-    token = netsnmp_mibindex_lookup( dirname );
-    if (token && stat(token, &idx_stat) == 0 && stat(dirname, &dir_stat) == 0) {
-        if (dir_stat.st_mtime < idx_stat.st_mtime) {
-            DEBUGMSGTL(("parse-mibs", "The index is good\n"));
-            if ((ip = fopen(token, "r")) != NULL) {
-                fgets(tmpstr, sizeof(tmpstr), ip); /* Skip dir line */
-                while (fscanf(ip, "%127s%c%299[^\n]%c", token, &space, tmpstr,
-		    &newline) == 4) {
-
-		    /*
-		     * If an overflow of the token or tmpstr buffers has been
-		     * found log a message and break out of the while loop,
-		     * thus the rest of the file tokens will be ignored.
-		     */
-		    if (space != ' ' || newline != '\n') {
-			snmp_log(LOG_ERR,
-			    "add_mibdir: strings scanned in from %s/%s " \
-			    "are too large.  count = %d\n ", dirname,
-			    ".index", count);
-			    break;
-		    }
-		   
-		    snprintf(tmpstr1, sizeof(tmpstr1), "%s/%s", dirname, tmpstr);
-                    tmpstr1[ sizeof(tmpstr1)-1 ] = 0;
-                    new_module(token, tmpstr1);
-                    count++;
-                }
-                fclose(ip);
-                return count;
-            } else
-                DEBUGMSGTL(("parse-mibs", "Can't read index\n"));
-        } else
-            DEBUGMSGTL(("parse-mibs", "Index outdated\n"));
-    } else
-        DEBUGMSGTL(("parse-mibs", "No index\n"));
-#endif
 
     filename_count = scan_directory(&filenames, dirname);
 
     if (filename_count >= 0) {
-        ip = netsnmp_mibindex_new(dirname);
         for (i = 0; i < filename_count; i++) {
-            if (add_mibfile(filenames[i], strrchr(filenames[i], '/'), ip) == 0)
+            if (add_mibfile(filenames[i], strrchr(filenames[i], '/')) == 0)
                 count++;
 	    free(filenames[i]);
         }
         File = oldFile;
-        if (ip)
-            fclose(ip);
         free(filenames);
         return (count);
     }
```
