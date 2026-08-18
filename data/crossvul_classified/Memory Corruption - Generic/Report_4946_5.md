# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4946_5
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4946_5`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 397-438 of the vulnerable file.

	hash_pos = kh_put_sha1_pos(eindex->positions, object->oid.hash, &hash_ret);
	if (hash_ret > 0) {
		if (eindex->count >= eindex->alloc) {
			eindex->alloc = (eindex->alloc + 16) * 3 / 2;
			REALLOC_ARRAY(eindex->objects, eindex->alloc);
			REALLOC_ARRAY(eindex->hashes, eindex->alloc);
		}

		bitmap_pos = eindex->count;
		eindex->objects[eindex->count] = object;
		eindex->hashes[eindex->count] = pack_name_hash(name);
		kh_value(eindex->positions, hash_pos) = bitmap_pos;
		eindex->count++;
	} else {
		bitmap_pos = kh_value(eindex->positions, hash_pos);
	}

	return bitmap_pos + bitmap_git.pack->num_objects;
}

static void show_object(struct object *object, struct strbuf *path,
			const char *last, void *data)
{
	struct bitmap *base = data;
	int bitmap_pos;

	bitmap_pos = bitmap_position(object->oid.hash);

	if (bitmap_pos < 0) {
		char *name = path_name(path, last);
		bitmap_pos = ext_index_add_object(object, name);
		free(name);
	}

	bitmap_set(base, bitmap_pos);
}

static void show_commit(struct commit *commit, void *data)
{
}

static int add_to_include_set(struct include_data *data,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -414,19 +414,15 @@
 	return bitmap_pos + bitmap_git.pack->num_objects;
 }
 
-static void show_object(struct object *object, struct strbuf *path,
-			const char *last, void *data)
+static void show_object(struct object *object, const char *name, void *data)
 {
 	struct bitmap *base = data;
 	int bitmap_pos;
 
 	bitmap_pos = bitmap_position(object->oid.hash);
 
-	if (bitmap_pos < 0) {
-		char *name = path_name(path, last);
+	if (bitmap_pos < 0)
 		bitmap_pos = ext_index_add_object(object, name);
-		free(name);
-	}
 
 	bitmap_set(base, bitmap_pos);
 }
@@ -894,9 +890,8 @@
 	size_t seen;
 };
 
-static void test_show_object(struct object *object,
-			     struct strbuf *path,
-			     const char *last, void *data)
+static void test_show_object(struct object *object, const char *name,
+			     void *data)
 {
 	struct bitmap_test_data *tdata = data;
 	int bitmap_pos;
```
