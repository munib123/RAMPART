# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4946_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4946_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 160-202 of the vulnerable file.

			}
		}
		strbuf_release(&buf);
	} else {
		if (graph_show_remainder(revs->graph))
			putchar('\n');
	}
	maybe_flush_or_die(stdout, "stdout");
	finish_commit(commit, data);
}

static void finish_commit(struct commit *commit, void *data)
{
	if (commit->parents) {
		free_commit_list(commit->parents);
		commit->parents = NULL;
	}
	free_commit_buffer(commit);
}

static void finish_object(struct object *obj,
			  struct strbuf *path, const char *name,
			  void *cb_data)
{
	struct rev_list_info *info = cb_data;
	if (obj->type == OBJ_BLOB && !has_object_file(&obj->oid))
		die("missing blob object '%s'", oid_to_hex(&obj->oid));
	if (info->revs->verify_objects && !obj->parsed && obj->type != OBJ_COMMIT)
		parse_object(obj->oid.hash);
}

static void show_object(struct object *obj,
			struct strbuf *path, const char *component,
			void *cb_data)
{
	struct rev_list_info *info = cb_data;
	finish_object(obj, path, component, cb_data);
	if (info->flags & REV_LIST_QUIET)
		return;
	show_object_with_name(stdout, obj, path, component);
}

static void show_edge(struct commit *commit)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -177,9 +177,7 @@
 	free_commit_buffer(commit);
 }
 
-static void finish_object(struct object *obj,
-			  struct strbuf *path, const char *name,
-			  void *cb_data)
+static void finish_object(struct object *obj, const char *name, void *cb_data)
 {
 	struct rev_list_info *info = cb_data;
 	if (obj->type == OBJ_BLOB && !has_object_file(&obj->oid))
@@ -188,15 +186,13 @@
 		parse_object(obj->oid.hash);
 }
 
-static void show_object(struct object *obj,
-			struct strbuf *path, const char *component,
-			void *cb_data)
+static void show_object(struct object *obj, const char *name, void *cb_data)
 {
 	struct rev_list_info *info = cb_data;
-	finish_object(obj, path, component, cb_data);
+	finish_object(obj, name, cb_data);
 	if (info->flags & REV_LIST_QUIET)
 		return;
-	show_object_with_name(stdout, obj, path, component);
+	show_object_with_name(stdout, obj, name);
 }
 
 static void show_edge(struct commit *commit)
```
