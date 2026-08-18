# CrossVul Fix Pair: NULL Pointer Dereference in c
**Pair ID:** 588_0
**Vulnerability Class:** NULL Pointer Dereference
**CWE:** CWE-476
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `588_0`)

## Vulnerability Information & PoC

## Description
NULL Pointer Dereference - NULL pointer dereference issues can occur through a number of flaws, including race conditions, and simple programming omissions.

## Vulnerable Code
```c
Lines 465-505 of the vulnerable file.

	{
	    if (!form->value)
		break;
	    p = form->value->ptr;
	}
	l = buf->currentLine;
	if (!l)
	    break;
	if (form->type == FORM_TEXTAREA) {
	    int n = a->y - buf->currentLine->linenumber;
	    if (n > 0)
		for (; l && n; l = l->prev, n--) ;
	    else if (n < 0)
		for (; l && n; l = l->prev, n++) ;
	    if (!l)
		break;
	}
	rows = form->rows ? form->rows : 1;
	col = COLPOS(l, a->start.pos);
	for (c_rows = 0; c_rows < rows; c_rows++, l = l->next) {
	    if (rows > 1) {
		pos = columnPos(l, col);
		a = retrieveAnchor(buf->formitem, l->linenumber, pos);
		if (a == NULL)
		    break;
		spos = a->start.pos;
		epos = a->end.pos;
	    }
	    if (a->start.line != a->end.line || spos > epos || epos >= l->len ||
		spos < 0 || epos < 0 || COLPOS(l, epos) < col)
		break;
	    pos = form_update_line(l, &p, spos, epos, COLPOS(l, epos) - col,
				   rows > 1,
				   form->type == FORM_INPUT_PASSWORD);
	    if (pos != epos) {
		shiftAnchorPosition(buf->href, buf->hmarklist,
				    a->start.line, spos, pos - epos);
		shiftAnchorPosition(buf->name, buf->hmarklist,
				    a->start.line, spos, pos - epos);
		shiftAnchorPosition(buf->img, buf->hmarklist,
				    a->start.line, spos, pos - epos);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -482,6 +482,8 @@
 	rows = form->rows ? form->rows : 1;
 	col = COLPOS(l, a->start.pos);
 	for (c_rows = 0; c_rows < rows; c_rows++, l = l->next) {
+	    if (l == NULL)
+		break;
 	    if (rows > 1) {
 		pos = columnPos(l, col);
 		a = retrieveAnchor(buf->formitem, l->linenumber, pos);
```
