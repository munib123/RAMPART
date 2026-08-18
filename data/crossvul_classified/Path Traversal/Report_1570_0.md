# CrossVul Fix Pair: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') in c
**Pair ID:** 1570_0
**Vulnerability Class:** Path Traversal
**CWE:** CWE-22
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1570_0`)

## Vulnerability Information & PoC

## Description
Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Many file operations are intended to take place within a restricted directory.

## Vulnerable Code
```c
Lines 114-154 of the vulnerable file.

#define strremovech libreport_strremovech
char *strremovech(char *str, int ch);
#define append_to_malloced_string libreport_append_to_malloced_string
char *append_to_malloced_string(char *mstr, const char *append);
#define skip_whitespace libreport_skip_whitespace
char* skip_whitespace(const char *s);
#define skip_non_whitespace libreport_skip_non_whitespace
char* skip_non_whitespace(const char *s);
/* Like strcpy but can copy overlapping strings. */
#define overlapping_strcpy libreport_overlapping_strcpy
void overlapping_strcpy(char *dst, const char *src);

#define concat_path_file libreport_concat_path_file
char *concat_path_file(const char *path, const char *filename);
/*
 * Used to construct a name in a different directory with the basename
 * similar to the old name, if possible.
 */
#define concat_path_basename libreport_concat_path_basename
char *concat_path_basename(const char *path, const char *filename);

/* A-la fgets, but malloced and of unlimited size */
#define xmalloc_fgets libreport_xmalloc_fgets
char *xmalloc_fgets(FILE *file);
/* Similar, but removes trailing \n */
#define xmalloc_fgetline libreport_xmalloc_fgetline
char *xmalloc_fgetline(FILE *file);
/* Useful for easy reading of various /proc files */
#define xmalloc_fopen_fgetline_fclose libreport_xmalloc_fopen_fgetline_fclose
char *xmalloc_fopen_fgetline_fclose(const char *filename);


/* On error, copyfd_XX prints error messages and returns -1 */
enum {
        COPYFD_SPARSE = 1 << 0,
};
#define copyfd_eof libreport_copyfd_eof
off_t copyfd_eof(int src_fd, int dst_fd, int flags);
#define copyfd_size libreport_copyfd_size
off_t copyfd_size(int src_fd, int dst_fd, off_t size, int flags);
#define copyfd_exact_size libreport_copyfd_exact_size
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -132,6 +132,12 @@
 #define concat_path_basename libreport_concat_path_basename
 char *concat_path_basename(const char *path, const char *filename);
 
+/* Allows all printable characters except '/',
+ * the string must not exceed 64 characters of length
+ * and must not equal neither "." nor ".." (these strings may appear in the string) */
+#define str_is_correct_filename libreport_str_is_correct_filename
+bool str_is_correct_filename(const char *str);
+
 /* A-la fgets, but malloced and of unlimited size */
 #define xmalloc_fgets libreport_xmalloc_fgets
 char *xmalloc_fgets(FILE *file);
```
