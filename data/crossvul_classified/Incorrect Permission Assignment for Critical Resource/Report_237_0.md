# CrossVul Fix Pair: Incorrect Permission Assignment for Critical Resource in c
**Pair ID:** 237_0
**Vulnerability Class:** Incorrect Permission Assignment for Critical Resource
**CWE:** CWE-732
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `237_0`)

## Vulnerability Information & PoC

## Description
Incorrect Permission Assignment for Critical Resource - When a resource is given a permission setting that provides access to a wider range of actors than required, it could lead to the exposure of sensitive information, or the modification of that reso...

## Vulnerable Code
```c
Lines 84-124 of the vulnerable file.

	if (M_fs_info(&info1, p1, M_FS_PATH_INFO_FLAGS_BASIC) == M_FS_ERROR_SUCCESS     &&
			M_fs_info(&info2, p2, M_FS_PATH_INFO_FLAGS_BASIC) == M_FS_ERROR_SUCCESS &&
			M_fs_info_get_type(info1) != M_FS_TYPE_DIR                              &&
			M_fs_info_get_type(info2) == M_FS_TYPE_DIR)
	{
		file_info_dir = M_TRUE;
	}
	M_fs_info_destroy(info1);
	M_fs_info_destroy(info2);

	if (!file_info_dir)
		return M_FALSE;

	bname   = M_fs_path_basename(p1, M_FS_SYSTEM_AUTO);
	*new_p2 = M_fs_path_join(p2, bname, M_FS_SYSTEM_AUTO);
	M_free(bname);

	return M_TRUE;
}

static M_bool M_fs_check_overwrite_allowed(const char *p1, const char *p2, M_uint32 mode)
{
	M_fs_info_t  *info = NULL;
	char         *pold = NULL;
	char         *pnew = NULL;
	M_fs_type_t   type;
	M_bool        ret  = M_TRUE;

	if (mode & M_FS_FILE_MODE_OVERWRITE)
		return M_TRUE;

	/* If we're not overwriting we need to verify existance.
 	 *
 	 * For files we need to check if the file name exists in the
	 * directory it's being copied to.
	 *
	 * For directories we need to check if the directory name
	 * exists in the directory it's being copied to.
	 */

	if (M_fs_info(&info, p1, M_FS_PATH_INFO_FLAGS_BASIC) != M_FS_ERROR_SUCCESS)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -101,6 +101,15 @@
 	return M_TRUE;
 }
 
+/* Used by copy and move to determine if we can write to the given path
+ * based on a file already existing there or not.
+ *
+ * access is used to determine existence because we don't want to overwrite
+ * if there already is a file. This is not guaranteed because if there is
+ * a race condition where a file is created after this check it will be
+ * overwritten. Not much we can do about that. It shouldn't pose a security
+ * issue since this is more of a request than a requirement.
+ */
 static M_bool M_fs_check_overwrite_allowed(const char *p1, const char *p2, M_uint32 mode)
 {
 	M_fs_info_t  *info = NULL;
@@ -129,8 +138,7 @@
 
 	if (type != M_FS_TYPE_DIR) {
 		/* File exists at path. */
-		if (M_fs_perms_can_access(p2, M_FS_PERMS_MODE_NONE) == M_FS_ERROR_SUCCESS)
-		{
+		if (M_fs_perms_can_access(p2, M_FS_PERMS_MODE_NONE) == M_FS_ERROR_SUCCESS) {
 			ret = M_FALSE;
 			goto done;
 		}
@@ -209,19 +217,6 @@
 	size_t         offset;
 	M_fs_error_t   res;
 
-	/* We're going to create/open/truncate the new file, then as we read the contents from the old file we'll write it
- 	 * to new file. */
-	if (M_fs_perms_can_access(path_new, M_FS_PERMS_MODE_NONE) == M_FS_ERROR_SUCCESS) {
-		/* Try to delete the file since we'll be overwrite it. This is so when we create the file we create it without
- 		 * any permissions and to ensure that anything that has the file already open won't be able to read the new
-		 * contents we're writing to the file or be able to change the perms. There is an unavoidable race condition
-		 * between deleting and creating the file where someone could create the file and have access. However,
-		 * depending on the OS they may have access even if the file is created with no perms... */
-		res = M_fs_delete(path_new, M_FALSE, NULL, M_FS_PROGRESS_NOEXTRA);
-		if (res != M_FS_ERROR_SUCCESS) {
-			return res;
-		}
-	}
 	/* Open the old file */
 	res = M_fs_file_open(&fd_old, path_old, M_FS_BUF_SIZE, M_FS_FILE_MODE_READ|M_FS_FILE_MODE_NOCREATE, NULL);
 	if (res != M_FS_ERROR_SUCCESS) {
@@ -236,6 +231,9 @@
 		}
 		perms = M_fs_info_get_perms(info);
 	}
+
+	/* We're going to create/open/truncate the new file, then as we read the contents from the old file we'll write it
+	 * to new file. */
 	res = M_fs_file_open(&fd_new, path_new, M_FS_BUF_SIZE, M_FS_FILE_MODE_WRITE|M_FS_FILE_MODE_OVERWRITE, perms);
 	M_fs_info_destroy(info);
 	if (res != M_FS_ERROR_SUCCESS) {
@@ -333,7 +331,7 @@
 	}
 
 	/* Normalize the old path and do basic checks that it exists. We'll leave really checking that the old path
- 	 * existing to rename because any check we perform may not be true when rename is called. */
+	 * existing to rename because any check we perform may not be true when rename is called. */
 	res = M_fs_path_norm(&norm_path_old, path_old, M_FS_PATH_NORM_RESALL, M_FS_SYSTEM_AUTO);
 	if (res != M_FS_ERROR_SUCCESS) {
 		M_free(norm_path_new);
@@ -351,7 +349,7 @@
 		return res;
 	}
 
- 	/* There is a race condition where the path could not exist but be created between the exists check and calling
+	/* There is a race condition where the path could not exist but be created between the exists check and calling
 	 * rename to move the file but there isn't much we can do in this case. copy will delete and the file so this
 	 * situation won't cause an error. */
 	if (!M_fs_check_overwrite_allowed(norm_path_old, norm_path_new, mode)) {
@@ -399,7 +397,7 @@
 			res = M_fs_delete(norm_path_old, M_TRUE, NULL, M_FS_PROGRESS_NOEXTRA);
 		} else {
 			/* Failure - Delete the new files that were copied but only if we are not overwriting. We don't
- 			 * want to remove any existing files (especially if the dest is a dir). */
+			 * want to remove any existing files (especially if the dest is a dir). */
 			if (!(mode & M_FS_FILE_MODE_OVERWRITE)) {
 				M_fs_delete(norm_path_new, M_TRUE, NULL, M_FS_PROGRESS_NOEXTRA);
 			}
@@ -407,7 +405,7 @@
 		}
 	} else {
 		/* Call the cb with the result of the move whether it was a success for fail. We call the cb only if the
- 		 * result of the move is not M_FS_ERROR_NOT_SAMEDEV because the copy operation will call the cb for us. */
+		 * result of the move is not M_FS_ERROR_NOT_SAMEDEV because the copy operation will call the cb for us. */
 		if (cb) {
 			M_fs_progress_set_result(progress, res);
 			if (!cb(progress)) {
@@ -465,7 +463,7 @@
 	}
 
 	/* Normalize the old path and do basic checks that it exists. We'll leave really checking that the old path
- 	 * existing to rename because any check we perform may not be true when rename is called. */
+	 * existing to rename because any check we perform may not be true when rename is called. */
 	res = M_fs_path_norm(&norm_path_old, path_old, M_FS_PATH_NORM_RESALL, M_FS_SYSTEM_AUTO);
 	if (res != M_FS_ERROR_SUCCESS) {
 		M_free(norm_path_new);
@@ -485,7 +483,7 @@
 
 	type = M_fs_info_get_type(info);
 
- 	/* There is a race condition where the path could not exist but be created between the exists check and calling
+	/* There is a race condition where the path could not exist but be created between the exists check and calling
 	 * rename to move the file but there isn't much we can do in this case. copy will delete and the file so this
 	 * situation won't cause an error. */
 	if (!M_fs_check_overwrite_allowed(norm_path_old, norm_path_new, mode)) {
@@ -497,7 +495,7 @@
 
 	entries = M_fs_dir_entries_create();
 	/* No need to destroy info  because it's now owned by entries and will be destroyed when entries is destroyed.
- 	 * M_FS_DIR_WALK_FILTER_READ_INFO_BASIC doesn't actually get the perms it's just there to ensure the info is
+	 * M_FS_DIR_WALK_FILTER_READ_INFO_BASIC doesn't actually get the perms it's just there to ensure the info is
 	 * stored in the entry. */
 	M_fs_dir_entries_insert(entries, M_fs_dir_walk_fill_entry(norm_path_new, NULL, type, info, M_FS_DIR_WALK_FILTER_READ_INFO_BASIC));
 	if (type == M_FS_TYPE_DIR) {
@@ -523,7 +521,7 @@
 
 			type = M_fs_dir_entry_get_type(entry);
 			/* The total isn't the total number of files but the total number of operations. 
- 			 * Making dirs and symlinks is one operation and copying a file will be split into
+			 * Making dirs and symlinks is one operation and copying a file will be split into
 			 * multiple operations. Copying uses the M_FS_BUF_SIZE to read and write in
 			 * chunks. We determine how many chunks will be needed to read the entire file and
 			 * use that for the number of operations for the file. */
@@ -600,7 +598,7 @@
 	}
 
 	/* Delete the file(s) if it could not be copied properly, but only if we are not overwriting.
- 	 * If we're overwriting then there could be other files in that location (especially if it's a dir). */
+	 * If we're overwriting then there could be other files in that location (especially if it's a dir). */
 	if (res != M_FS_ERROR_SUCCESS && !(mode & M_FS_FILE_MODE_OVERWRITE)) {
 		M_fs_delete(path_new, M_TRUE, NULL, M_FS_PROGRESS_NOEXTRA);
 	}
@@ -659,7 +657,7 @@
 	entries = M_fs_dir_entries_create();
 
 	/* Recursive directory deletion isn't intuitive. We have to generate a list of files and delete the list.
- 	 * We cannot delete as walk because not all file systems support that operation. The walk; delete; behavior
+	 * We cannot delete as walk because not all file systems support that operation. The walk; delete; behavior
 	 * is undefined in Posix and HFS is known to skip files if the directory contents is modifies as the
 	 * directory is being walked. */
 	if (type == M_FS_TYPE_DIR && remove_children) {
@@ -671,7 +669,7 @@
 	}
 
 	/* Add the original path to the list of entries. This may be the only entry in the list. We need to add
- 	 * it after a potential walk because we can't delete a directory that isn't empty.
+	 * it after a potential walk because we can't delete a directory that isn't empty.
 	 * Note: 
 	 *   - The info will be owned by the entry and destroyed when it is destroyed. 
... (diff truncated)
```
