# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 395_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `395_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1432-1472 of the vulnerable file.

            if (ptr->used && ptr - subr_tab > subr_max)
                subr_max = ptr - subr_tab;
}

static void t1_check_unusual_charstring(void)
{
    char *p = strstr(t1_line_array, charstringname) + strlen(charstringname);
    int i;
    /* if no number follows "/CharStrings", let's read the next line */
    if (sscanf(p, "%i", &i) != 1) {
        /* pdftex_warn("no number found after `%s', I assume it's on the next line",
                    charstringname); */
        strcpy(t1_buf_array, t1_line_array);

        /* t1_getline always appends EOL to t1_line_array; let's change it to
         * space before appending the next line
         */
        *(strend(t1_buf_array) - 1) = ' ';

        t1_getline();
        strcat(t1_buf_array, t1_line_array);
        strcpy(t1_line_array, t1_buf_array);
        t1_line_ptr = eol(t1_line_array);
    }
}

static void t1_subset_charstrings(void)
{
    cs_entry *ptr;

    /* at this point t1_line_array contains "/CharStrings".
       when we hit a case like this:
         dup/CharStrings
         229 dict dup begin
       we read the next line and concatenate to t1_line_array before moving on
    */
    t1_check_unusual_charstring();

    cs_size_pos = strstr(t1_line_array, charstringname)
                  + strlen(charstringname) - t1_line_array + 1;
    /* cs_size_pos points to the number indicating
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1449,7 +1449,9 @@
         *(strend(t1_buf_array) - 1) = ' ';
 
         t1_getline();
+        alloc_array(t1_buf, strlen(t1_line_array) + strlen(t1_buf_array) + 1, T1_BUF_SIZE);
         strcat(t1_buf_array, t1_line_array);
+        alloc_array(t1_line, strlen(t1_buf_array) + 1, T1_BUF_SIZE);
         strcpy(t1_line_array, t1_buf_array);
         t1_line_ptr = eol(t1_line_array);
     }
```
