# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 3989_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3989_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 1254-1294 of the vulnerable file.


	return git_vector_insert(&data->remove_conflicts, (char *)name);
}

static int checkout_get_remove_conflicts(
	checkout_data *data,
	git_iterator *workdir,
	git_vector *pathspec)
{
	if ((data->strategy & GIT_CHECKOUT_DONT_UPDATE_INDEX) != 0)
		return 0;

	return checkout_conflicts_foreach(data, data->index, workdir, pathspec, checkout_conflict_append_remove, data);
}

static int checkout_verify_paths(
	git_repository *repo,
	int action,
	git_diff_delta *delta)
{
	unsigned int flags = GIT_PATH_REJECT_WORKDIR_DEFAULTS;

	if (action & CHECKOUT_ACTION__REMOVE) {
		if (!git_path_isvalid(repo, delta->old_file.path, delta->old_file.mode, flags)) {
			git_error_set(GIT_ERROR_CHECKOUT, "cannot remove invalid path '%s'", delta->old_file.path);
			return -1;
		}
	}

	if (action & ~CHECKOUT_ACTION__REMOVE) {
		if (!git_path_isvalid(repo, delta->new_file.path, delta->new_file.mode, flags)) {
			git_error_set(GIT_ERROR_CHECKOUT, "cannot checkout to invalid path '%s'", delta->new_file.path);
			return -1;
		}
	}

	return 0;
}

static int checkout_get_actions(
	uint32_t **actions_ptr,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1271,7 +1271,7 @@
 	int action,
 	git_diff_delta *delta)
 {
-	unsigned int flags = GIT_PATH_REJECT_WORKDIR_DEFAULTS;
+	unsigned int flags = GIT_PATH_REJECT_WORKDIR_DEFAULTS | GIT_PATH_REJECT_DOT_GIT_NTFS;
 
 	if (action & CHECKOUT_ACTION__REMOVE) {
 		if (!git_path_isvalid(repo, delta->old_file.path, delta->old_file.mode, flags)) {
```
