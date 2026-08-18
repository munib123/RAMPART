# CrossVul Fix Pair: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') in c
**Pair ID:** 4400_1
**Vulnerability Class:** Code Injection
**CWE:** CWE-74
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4400_1`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection') - Software or other automated logic has certain assumptions about what constitutes data and control respectively.

## Vulnerable Code
```c
Lines 238-278 of the vulnerable file.


static int
rndr_highlight(struct buf *ob, const struct buf *text, void *opaque)
{
	if (!text || !text->size)
		return 0;

	BUFPUTSL(ob, "<mark>");
	bufput(ob, text->data, text->size);
	BUFPUTSL(ob, "</mark>");

	return 1;
}

static int
rndr_quote(struct buf *ob, const struct buf *text, void *opaque)
{
	if (!text || !text->size)
		return 0;

	BUFPUTSL(ob, "<q>");
	bufput(ob, text->data, text->size);
	BUFPUTSL(ob, "</q>");

	return 1;
}

static int
rndr_linebreak(struct buf *ob, void *opaque)
{
	struct html_renderopt *options = opaque;
	bufputs(ob, USE_XHTML(options) ? "<br/>\n" : "<br>\n");
	return 1;
}

static void
rndr_header_anchor(struct buf *out, const struct buf *anchor)
{
	static const char *STRIPPED = " -&+$,/:;=?@\"#{}|^~[]`\\*()%.!'";

	const uint8_t *a = anchor->data;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -255,8 +255,15 @@
 	if (!text || !text->size)
 		return 0;
 
+	struct html_renderopt *options = opaque;
+
 	BUFPUTSL(ob, "<q>");
-	bufput(ob, text->data, text->size);
+
+	if (options->flags & HTML_ESCAPE)
+		escape_html(ob, text->data, text->size);
+	else
+		bufput(ob, text->data, text->size);
+
 	BUFPUTSL(ob, "</q>");
 
 	return 1;
```
