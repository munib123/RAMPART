# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4946_4
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4946_4`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 131-172 of the vulnerable file.

{
	unsigned int i;
	for (i = 0; i < seen_objects_nr; ++i) {
		seen_objects[i]->flags &= ~(SEEN | ADDED | SHOWN);
	}
	seen_objects_nr = 0;
}

static uint32_t find_object_pos(const unsigned char *sha1)
{
	struct object_entry *entry = packlist_find(writer.to_pack, sha1, NULL);

	if (!entry) {
		die("Failed to write bitmap index. Packfile doesn't have full closure "
			"(object %s is missing)", sha1_to_hex(sha1));
	}

	return entry->in_pack_pos;
}

static void show_object(struct object *object, struct strbuf *path,
			const char *last, void *data)
{
	struct bitmap *base = data;
	bitmap_set(base, find_object_pos(object->oid.hash));
	mark_as_seen(object);
}

static void show_commit(struct commit *commit, void *data)
{
	mark_as_seen((struct object *)commit);
}

static int
add_to_include_set(struct bitmap *base, struct commit *commit)
{
	khiter_t hash_pos;
	uint32_t bitmap_pos = find_object_pos(commit->object.oid.hash);

	if (bitmap_get(base, bitmap_pos))
		return 0;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -148,8 +148,7 @@
 	return entry->in_pack_pos;
 }
 
-static void show_object(struct object *object, struct strbuf *path,
-			const char *last, void *data)
+static void show_object(struct object *object, const char *name, void *data)
 {
 	struct bitmap *base = data;
 	bitmap_set(base, find_object_pos(object->oid.hash));
```
