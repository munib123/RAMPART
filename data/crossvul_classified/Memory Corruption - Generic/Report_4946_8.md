# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 4946_8
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4946_8`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 242-283 of the vulnerable file.

			       const struct option *options,
			       const char * const usagestr[]);
#define REVARG_CANNOT_BE_FILENAME 01
#define REVARG_COMMITTISH 02
extern int handle_revision_arg(const char *arg, struct rev_info *revs,
			       int flags, unsigned revarg_opt);

extern void reset_revision_walk(void);
extern int prepare_revision_walk(struct rev_info *revs);
extern struct commit *get_revision(struct rev_info *revs);
extern char *get_revision_mark(const struct rev_info *revs,
			       const struct commit *commit);
extern void put_revision_mark(const struct rev_info *revs,
			      const struct commit *commit);

extern void mark_parents_uninteresting(struct commit *commit);
extern void mark_tree_uninteresting(struct tree *tree);

char *path_name(struct strbuf *path, const char *name);

extern void show_object_with_name(FILE *, struct object *,
				  struct strbuf *, const char *);

extern void add_pending_object(struct rev_info *revs,
			       struct object *obj, const char *name);
extern void add_pending_sha1(struct rev_info *revs,
			     const char *name, const unsigned char *sha1,
			     unsigned int flags);

extern void add_head_to_pending(struct rev_info *);
extern void add_reflogs_to_pending(struct rev_info *, unsigned int flags);
extern void add_index_objects_to_pending(struct rev_info *, unsigned int flags);

enum commit_action {
	commit_ignore,
	commit_show,
	commit_error
};

extern enum commit_action get_commit_action(struct rev_info *revs,
					    struct commit *commit);
extern enum commit_action simplify_commit(struct rev_info *revs,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -259,8 +259,7 @@
 
 char *path_name(struct strbuf *path, const char *name);
 
-extern void show_object_with_name(FILE *, struct object *,
-				  struct strbuf *, const char *);
+extern void show_object_with_name(FILE *, struct object *, const char *);
 
 extern void add_pending_object(struct rev_info *revs,
 			       struct object *obj, const char *name);
```
