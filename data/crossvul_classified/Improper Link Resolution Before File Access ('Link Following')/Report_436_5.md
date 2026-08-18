# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in c
**Pair ID:** 436_5
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `436_5`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```c
Lines 1188-1228 of the vulnerable file.


	ret = stat(tfile->file_path, &statb);
	if (!ret) {
		if (track_file_init == TRACK_FILE_CREATE) {
			/* The file exists */
			return;
		}
		if ((statb.st_mode & S_IFMT) != S_IFREG) {
			/* It is not a regular file */
			report_config_error(CONFIG_GENERAL_ERROR, "Cannot initialise track file %s - it is not a regular file", tfile->fname);
			return;
		}

		/* Don't overwrite a file on reload */
		if (reload)
			return;
	}

	if (!__test_bit(CONFIG_TEST_BIT, &debug)) {
		/* Write the value to the file */
		if ((tf = fopen(tfile->file_path, "w"))) {
			fprintf(tf, "%d\n", track_file_init_value);
			fclose(tf);
		}
		else
			report_config_error(CONFIG_GENERAL_ERROR, "Unable to initialise track file %s", tfile->fname);
	}
}
static void
vrrp_vscript_init_fail_handler(__attribute__((unused)) vector_t *strvec)
{
	vrrp_script_t *vscript = LIST_TAIL_DATA(vrrp_data->vrrp_script);
	vscript->init_state = SCRIPT_INIT_STATE_FAILED;
}
static void
vrrp_version_handler(vector_t *strvec)
{
	vrrp_t *vrrp = LIST_TAIL_DATA(vrrp_data->vrrp);
	int version;

	if (!read_int_strvec(strvec, 1, &version, 2, 3, true)) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1205,7 +1205,7 @@
 
 	if (!__test_bit(CONFIG_TEST_BIT, &debug)) {
 		/* Write the value to the file */
-		if ((tf = fopen(tfile->file_path, "w"))) {
+		if ((tf = fopen_safe(tfile->file_path, "w"))) {
 			fprintf(tf, "%d\n", track_file_init_value);
 			fclose(tf);
 		}
```
