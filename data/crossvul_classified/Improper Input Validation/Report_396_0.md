# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 396_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `396_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 48-88 of the vulnerable file.

	FUNC(MISSING_SPACE_BEFORE_DATE, ERROR) \
	FUNC(MISSING_SPACE_BEFORE_EMAIL, ERROR) \
	FUNC(MISSING_TAG, ERROR) \
	FUNC(MISSING_TAG_ENTRY, ERROR) \
	FUNC(MISSING_TAG_OBJECT, ERROR) \
	FUNC(MISSING_TREE, ERROR) \
	FUNC(MISSING_TREE_OBJECT, ERROR) \
	FUNC(MISSING_TYPE, ERROR) \
	FUNC(MISSING_TYPE_ENTRY, ERROR) \
	FUNC(MULTIPLE_AUTHORS, ERROR) \
	FUNC(TAG_OBJECT_NOT_TAG, ERROR) \
	FUNC(TREE_NOT_SORTED, ERROR) \
	FUNC(UNKNOWN_TYPE, ERROR) \
	FUNC(ZERO_PADDED_DATE, ERROR) \
	FUNC(GITMODULES_MISSING, ERROR) \
	FUNC(GITMODULES_BLOB, ERROR) \
	FUNC(GITMODULES_PARSE, ERROR) \
	FUNC(GITMODULES_NAME, ERROR) \
	FUNC(GITMODULES_SYMLINK, ERROR) \
	FUNC(GITMODULES_URL, ERROR) \
	/* warnings */ \
	FUNC(BAD_FILEMODE, WARN) \
	FUNC(EMPTY_NAME, WARN) \
	FUNC(FULL_PATHNAME, WARN) \
	FUNC(HAS_DOT, WARN) \
	FUNC(HAS_DOTDOT, WARN) \
	FUNC(HAS_DOTGIT, WARN) \
	FUNC(NULL_SHA1, WARN) \
	FUNC(ZERO_PADDED_FILEMODE, WARN) \
	FUNC(NUL_IN_COMMIT, WARN) \
	/* infos (reported as warnings, but ignored by default) */ \
	FUNC(BAD_TAG_NAME, INFO) \
	FUNC(MISSING_TAGGER_ENTRY, INFO)

#define MSG_ID(id, msg_type) FSCK_MSG_##id,
enum fsck_msg_id {
	FOREACH_MSG_ID(MSG_ID)
	FSCK_MSG_MAX
};
#undef MSG_ID

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -65,6 +65,7 @@
 	FUNC(GITMODULES_NAME, ERROR) \
 	FUNC(GITMODULES_SYMLINK, ERROR) \
 	FUNC(GITMODULES_URL, ERROR) \
+	FUNC(GITMODULES_PATH, ERROR) \
 	/* warnings */ \
 	FUNC(BAD_FILEMODE, WARN) \
 	FUNC(EMPTY_NAME, WARN) \
@@ -952,6 +953,12 @@
 				    FSCK_MSG_GITMODULES_URL,
 				    "disallowed submodule url: %s",
 				    value);
+	if (!strcmp(key, "path") && value &&
+	    looks_like_command_line_option(value))
+		data->ret |= report(data->options, data->obj,
+				    FSCK_MSG_GITMODULES_PATH,
+				    "disallowed submodule path: %s",
+				    value);
 	free(name);
 
 	return 0;
```
