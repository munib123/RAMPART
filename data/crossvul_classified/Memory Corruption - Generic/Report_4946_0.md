# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4946_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4946_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 2267-2309 of the vulnerable file.

		}
		if (get_sha1_hex(line, sha1))
			die("expected sha1, got garbage:\n %s", line);

		add_preferred_base_object(line+41);
		add_object_entry(sha1, 0, line+41, 0);
	}
}

#define OBJECT_ADDED (1u<<20)

static void show_commit(struct commit *commit, void *data)
{
	add_object_entry(commit->object.oid.hash, OBJ_COMMIT, NULL, 0);
	commit->object.flags |= OBJECT_ADDED;

	if (write_bitmap_index)
		index_commit_for_bitmap(commit);
}

static void show_object(struct object *obj,
			struct strbuf *path, const char *last,
			void *data)
{
	char *name = path_name(path, last);

	add_preferred_base_object(name);
	add_object_entry(obj->oid.hash, obj->type, name, 0);
	obj->flags |= OBJECT_ADDED;

	/*
	 * We will have generated the hash from the name,
	 * but not saved a pointer to it - we can free it
	 */
	free((char *)name);
}

static void show_edge(struct commit *commit)
{
	add_preferred_base(commit->object.oid.hash);
}

struct in_pack_object {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2284,21 +2284,11 @@
 		index_commit_for_bitmap(commit);
 }
 
-static void show_object(struct object *obj,
-			struct strbuf *path, const char *last,
-			void *data)
-{
-	char *name = path_name(path, last);
-
+static void show_object(struct object *obj, const char *name, void *data)
+{
 	add_preferred_base_object(name);
 	add_object_entry(obj->oid.hash, obj->type, name, 0);
 	obj->flags |= OBJECT_ADDED;
-
-	/*
-	 * We will have generated the hash from the name,
-	 * but not saved a pointer to it - we can free it
-	 */
-	free((char *)name);
 }
 
 static void show_edge(struct commit *commit)
@@ -2480,8 +2470,7 @@
 }
 
 static void record_recent_object(struct object *obj,
-				 struct strbuf *path,
-				 const char *last,
+				 const char *name,
 				 void *data)
 {
 	sha1_array_append(&recent_objects, obj->oid.hash);
```
