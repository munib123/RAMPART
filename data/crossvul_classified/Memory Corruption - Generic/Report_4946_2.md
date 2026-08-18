# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4946_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4946_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 1-39 of the vulnerable file.

#include "cache.h"
#include "tag.h"
#include "commit.h"
#include "tree.h"
#include "blob.h"
#include "diff.h"
#include "tree-walk.h"
#include "revision.h"
#include "list-objects.h"

static void process_blob(struct rev_info *revs,
			 struct blob *blob,
			 show_object_fn show,
			 struct strbuf *path,
			 const char *name,
			 void *cb_data)
{
	struct object *obj = &blob->object;

	if (!revs->blob_objects)
		return;
	if (!obj)
		die("bad blob object");
	if (obj->flags & (UNINTERESTING | SEEN))
		return;
	obj->flags |= SEEN;
	show(obj, path, name, cb_data);
}

/*
 * Processing a gitlink entry currently does nothing, since
 * we do not recurse into the subproject.
 *
 * We *could* eventually add a flag that actually does that,
 * which would involve:
 *  - is the subproject actually checked out?
 *  - if so, see if the subproject has already been added
 *    to the alternates list, and add it if not.
 *  - process the commit (or tag) the gitlink points to
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -16,6 +16,7 @@
 			 void *cb_data)
 {
 	struct object *obj = &blob->object;
+	size_t pathlen;
 
 	if (!revs->blob_objects)
 		return;
@@ -24,7 +25,11 @@
 	if (obj->flags & (UNINTERESTING | SEEN))
 		return;
 	obj->flags |= SEEN;
-	show(obj, path, name, cb_data);
+
+	pathlen = path->len;
+	strbuf_addstr(path, name);
+	show(obj, path->buf, cb_data);
+	strbuf_setlen(path, pathlen);
 }
 
 /*
@@ -86,9 +91,8 @@
 	}
 
 	obj->flags |= SEEN;
-	show(obj, base, name, cb_data);
-
 	strbuf_addstr(base, name);
+	show(obj, base->buf, cb_data);
 	if (base->len)
 		strbuf_addch(base, '/');
 
@@ -207,7 +211,7 @@
 			continue;
 		if (obj->type == OBJ_TAG) {
 			obj->flags |= SEEN;
-			show_object(obj, NULL, name, data);
+			show_object(obj, name, data);
 			continue;
 		}
 		if (!path)
@@ -219,7 +223,7 @@
 		}
 		if (obj->type == OBJ_BLOB) {
 			process_blob(revs, (struct blob *)obj, show_object,
-				     NULL, path, data);
+				     &base, path, data);
 			continue;
 		}
 		die("unknown pending object %s (%s)",
```
