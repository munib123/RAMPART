# CrossVul Fix Pair: Loop with Unreachable Exit Condition ('Infinite Loop') in c
**Pair ID:** 587_0
**Vulnerability Class:** Loop with Unreachable Exit Condition ('Infinite Loop')
**CWE:** CWE-835
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `587_0`)

## Vulnerability Information & PoC

## Description
Loop with Unreachable Exit Condition ('Infinite Loop') - If the loop can be influenced by an attacker, this weakness could allow attackers to consume excessive resources such as CPU or memory.

## Vulnerable Code
```c
Lines 2339-2379 of the vulnerable file.

		     char *line, struct table_mode *mode, int indent, int cmd)
{
    int offset;
    if (mode->indent_level <= 0 && indent == -1)
	return;
    if (mode->indent_level >= CHAR_MAX && indent == 1)
	return;
    setwidth(tbl, mode);
    feed_table_inline_tag(tbl, line, mode, -1);
    clearcontentssize(tbl, mode);
    if (indent == 1) {
	mode->indent_level++;
	if (mode->indent_level <= MAX_INDENT_LEVEL)
	    tbl->indent += INDENT_INCR;
    }
    else if (indent == -1) {
	mode->indent_level--;
	if (mode->indent_level < MAX_INDENT_LEVEL)
	    tbl->indent -= INDENT_INCR;
    }
    offset = tbl->indent;
    if (cmd == HTML_DT) {
	if (mode->indent_level > 0 && mode->indent_level <= MAX_INDENT_LEVEL)
	    offset -= INDENT_INCR;
    }
    if (tbl->indent > 0) {
	check_minimum0(tbl, 0);
	addcontentssize(tbl, offset);
    }
}

static void
table_close_select(struct table *tbl, struct table_mode *mode, int width)
{
    Str tmp = process_n_select();
    mode->pre_mode &= ~TBLM_INSELECT;
    mode->end_tag = 0;
    feed_table1(tbl, tmp, mode, width);
}

static void
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2356,10 +2356,14 @@
 	if (mode->indent_level < MAX_INDENT_LEVEL)
 	    tbl->indent -= INDENT_INCR;
     }
+    if (tbl->indent < 0)
+	tbl->indent = 0;
     offset = tbl->indent;
     if (cmd == HTML_DT) {
 	if (mode->indent_level > 0 && mode->indent_level <= MAX_INDENT_LEVEL)
 	    offset -= INDENT_INCR;
+	if (offset < 0)
+	    offset = 0;
     }
     if (tbl->indent > 0) {
 	check_minimum0(tbl, 0);
```
