# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4946_6
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4946_6`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 26-67 of the vulnerable file.

		       int flag, void *cb_data)
{
	struct rev_info *revs = (struct rev_info *)cb_data;
	struct object *object;

	if ((flag & REF_ISSYMREF) && (flag & REF_ISBROKEN)) {
		warning("symbolic ref is dangling: %s", path);
		return 0;
	}

	object = parse_object_or_die(oid->hash, path);
	add_pending_object(revs, object, "");

	return 0;
}

/*
 * The traversal will have already marked us as SEEN, so we
 * only need to handle any progress reporting here.
 */
static void mark_object(struct object *obj, struct strbuf *path,
			const char *name, void *data)
{
	update_progress(data);
}

static void mark_commit(struct commit *c, void *data)
{
	mark_object(&c->object, NULL, NULL, data);
}

struct recent_data {
	struct rev_info *revs;
	unsigned long timestamp;
};

static void add_recent_object(const unsigned char *sha1,
			      unsigned long mtime,
			      struct recent_data *data)
{
	struct object *obj;
	enum object_type type;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -43,15 +43,14 @@
  * The traversal will have already marked us as SEEN, so we
  * only need to handle any progress reporting here.
  */
-static void mark_object(struct object *obj, struct strbuf *path,
-			const char *name, void *data)
+static void mark_object(struct object *obj, const char *name, void *data)
 {
 	update_progress(data);
 }
 
 static void mark_commit(struct commit *c, void *data)
 {
-	mark_object(&c->object, NULL, NULL, data);
+	mark_object(&c->object, NULL, data);
 }
 
 struct recent_data {
```
