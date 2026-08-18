# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 2561_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2561_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 539-579 of the vulnerable file.

			*p++ = *str;
		else {
			*p++ = '^';
			*p++ = *str + 'A'-1;
		}
		str++;
	}
	*p = '\0';

	return ret;
}

/* Get time in human readable form with localtime() + asctime() */
char *my_asctime(time_t t)
{
	struct tm *tm;
	char *str;
        int len;

	tm = localtime(&t);
	str = g_strdup(asctime(tm));

	len = strlen(str);
	if (len > 0) str[len-1] = '\0';
        return str;
}

/* Returns number of columns needed to print items.
   save_column_widths is filled with length of each column. */
int get_max_column_count(GSList *items, COLUMN_LEN_FUNC len_func,
			 int max_width, int max_columns,
			 int item_extra, int item_min_size,
			 int **save_column_widths, int *rows)
{
        GSList *tmp;
	int **columns, *columns_width, *columns_rows;
	int item_pos, items_count;
	int ret, len, max_len, n, col;

	items_count = g_slist_length(items);
	if (items_count == 0) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -556,6 +556,9 @@
         int len;
 
 	tm = localtime(&t);
+	if (tm == NULL)
+	    return g_strdup("???");
+
 	str = g_strdup(asctime(tm));
 
 	len = strlen(str);
```
