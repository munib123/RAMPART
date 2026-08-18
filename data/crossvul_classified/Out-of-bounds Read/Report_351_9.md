# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 351_9
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `351_9`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 458-498 of the vulnerable file.

	file->status = SC_FILE_STATUS_ACTIVATED;
	file->magic = SC_FILE_MAGIC;

	LOG_FUNC_RETURN(card->ctx, SC_SUCCESS);
}


static int
auth_select_file(struct sc_card *card, const struct sc_path *in_path,
				 struct sc_file **file_out)
{
	struct sc_path path;
	struct sc_file *tmp_file = NULL;
	size_t offs, ii;
	int rv;

	LOG_FUNC_CALLED(card->ctx);
	assert(card != NULL && in_path != NULL);

	memcpy(&path, in_path, sizeof(struct sc_path));

	sc_log(card->ctx, "in_path; type=%d, path=%s, out %p",
			in_path->type, sc_print_path(in_path), file_out);
	sc_log(card->ctx, "current path; type=%d, path=%s",
			auth_current_df->path.type, sc_print_path(&auth_current_df->path));
	if (auth_current_ef)
		sc_log(card->ctx, "current file; type=%d, path=%s",
				auth_current_ef->path.type, sc_print_path(&auth_current_ef->path));

	if (path.type == SC_PATH_TYPE_PARENT || path.type == SC_PATH_TYPE_FILE_ID)   {
		sc_file_free(auth_current_ef);
		auth_current_ef = NULL;

		rv = iso_ops->select_file(card, &path, &tmp_file);
		LOG_TEST_RET(card->ctx, rv, "select file failed");
		if (!tmp_file)
			return SC_ERROR_OBJECT_NOT_FOUND;

		if (path.type == SC_PATH_TYPE_PARENT)   {
			memcpy(&tmp_file->path, &auth_current_df->path, sizeof(struct sc_path));
			if (tmp_file->path.len > 2)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -476,6 +476,9 @@
 
 	memcpy(&path, in_path, sizeof(struct sc_path));
 
+	if (!auth_current_df)
+		return SC_ERROR_OBJECT_NOT_FOUND;
+
 	sc_log(card->ctx, "in_path; type=%d, path=%s, out %p",
 			in_path->type, sc_print_path(in_path), file_out);
 	sc_log(card->ctx, "current path; type=%d, path=%s",
@@ -2113,6 +2116,10 @@
 	bn[1].data = NULL;
 
 	LOG_FUNC_CALLED(card->ctx);
+
+	if (!auth_current_ef)
+		LOG_TEST_RET(card->ctx, SC_ERROR_INVALID_ARGUMENTS, "Invalid auth_current_ef");
+
 	sc_log(card->ctx,
 	       "offset %i; size %"SC_FORMAT_LEN_SIZE_T"u; flags 0x%lX",
 	       offset, count, flags);
```
