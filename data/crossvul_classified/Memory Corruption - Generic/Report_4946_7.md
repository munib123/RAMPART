# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4946_7
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4946_7`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 8-48 of the vulnerable file.

#include "revision.h"
#include "graph.h"
#include "grep.h"
#include "reflog-walk.h"
#include "patch-ids.h"
#include "decorate.h"
#include "log-tree.h"
#include "string-list.h"
#include "line-log.h"
#include "mailmap.h"
#include "commit-slab.h"
#include "dir.h"
#include "cache-tree.h"
#include "bisect.h"

volatile show_early_output_fn_t show_early_output;

static const char *term_bad;
static const char *term_good;

char *path_name(struct strbuf *path, const char *name)
{
	struct strbuf ret = STRBUF_INIT;
	if (path)
		strbuf_addbuf(&ret, path);
	strbuf_addstr(&ret, name);
	return strbuf_detach(&ret, NULL);
}

void show_object_with_name(FILE *out, struct object *obj,
			   struct strbuf *path, const char *component)
{
	char *name = path_name(path, component);
	char *p;

	fprintf(out, "%s ", oid_to_hex(&obj->oid));
	for (p = name; *p && *p != '\n'; p++)
		fputc(*p, out);
	fputc('\n', out);

	free(name);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -25,27 +25,14 @@
 static const char *term_bad;
 static const char *term_good;
 
-char *path_name(struct strbuf *path, const char *name)
-{
-	struct strbuf ret = STRBUF_INIT;
-	if (path)
-		strbuf_addbuf(&ret, path);
-	strbuf_addstr(&ret, name);
-	return strbuf_detach(&ret, NULL);
-}
-
-void show_object_with_name(FILE *out, struct object *obj,
-			   struct strbuf *path, const char *component)
-{
-	char *name = path_name(path, component);
-	char *p;
+void show_object_with_name(FILE *out, struct object *obj, const char *name)
+{
+	const char *p;
 
 	fprintf(out, "%s ", oid_to_hex(&obj->oid));
 	for (p = name; *p && *p != '\n'; p++)
 		fputc(*p, out);
 	fputc('\n', out);
-
-	free(name);
 }
 
 static void mark_blob_uninteresting(struct blob *blob)
```
