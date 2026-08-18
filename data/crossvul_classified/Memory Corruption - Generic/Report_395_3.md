# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 395_3
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `395_3`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1564-1604 of the vulnerable file.

    |/CharStrings|. When we hit a case like this:

    \starttyping
     dup/CharStrings
     229 dict dup begin
    \stoptyping

    we read the next line and concatenate to |t1_line_array| before moving on.
    That is what |t1_check_unusual_charstring| is for.

*/

static void t1_check_unusual_charstring(void)
{
    char *p = strstr(t1_line_array, charstringname) + strlen(charstringname);
    int i;
    /*tex If no number follows |/CharStrings|, let's read the next line. */
    if (sscanf(p, "%i", &i) != 1) {
        strcpy(t1_buf_array, t1_line_array);
        t1_getline();
        strcat(t1_buf_array, t1_line_array);
        strcpy(t1_line_array, t1_buf_array);
        t1_line_ptr = eol(t1_line_array);
    }
}

static void t1_subset_charstrings(PDF pdf)
{
    cs_entry *ptr;
    t1_check_unusual_charstring();
    cs_size_pos = (int) (strstr(t1_line_array, charstringname) + strlen(charstringname) - t1_line_array + 1);
    /*tex |cs_size_pos| points to the number indicating dict size after |/CharStrings|. */
    cs_size = (int) t1_scan_num(t1_line_array + cs_size_pos, 0);
    cs_ptr = cs_tab = xtalloc((unsigned) cs_size, cs_entry);
    for (ptr = cs_tab; ptr - cs_tab < cs_size; ptr++)
        init_cs_entry(ptr);
    cs_notdef = NULL;
    cs_dict_start = xstrdup(t1_line_array);
    t1_getline();
    while (t1_cslen) {
        store_cs();
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1581,7 +1581,9 @@
     if (sscanf(p, "%i", &i) != 1) {
         strcpy(t1_buf_array, t1_line_array);
         t1_getline();
+        alloc_array(t1_buf, strlen(t1_line_array) + strlen(t1_buf_array) + 1, T1_BUF_SIZE);
         strcat(t1_buf_array, t1_line_array);
+        alloc_array(t1_line, strlen(t1_buf_array) + 1, T1_BUF_SIZE);
         strcpy(t1_line_array, t1_buf_array);
         t1_line_ptr = eol(t1_line_array);
     }
```
