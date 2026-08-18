# CrossVul Fix Pair: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in c
**Pair ID:** 4099_0
**Vulnerability Class:** OS Command Injection
**CWE:** CWE-78
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4099_0`)

## Vulnerability Information & PoC

## Description
Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') - This could allow attackers to execute unexpected, dangerous commands directly on the operating system.

## Vulnerable Code
```c
Lines 1-43 of the vulnerable file.

/* radare - LGPL - Copyright 2014-2017 - inisider */

#include <string.h>
#include <r_util.h>
#include <r_core.h>
#include "pdb_downloader.h"

static bool checkExtract() {
#if __WINDOWS__
	if (r_sys_cmd ("expand -? >nul") != 0) {
		return false;
	}
#else
	if (r_sys_cmd ("cabextract -v > /dev/null") != 0) {
		return false;
	}
#endif
	return true;
}

static bool checkCurl() {
	const char nul[] = R_SYS_DEVNULL;
	if (r_sys_cmdf ("curl --version > %s", nul) != 0) {
		return false;
	}
	return true;
}

static int download(struct SPDBDownloader *pd) {
	SPDBDownloaderOpt *opt = pd->opt;
	char *curl_cmd = NULL;
	char *extractor_cmd = NULL;
	char *abspath_to_archive = NULL;
	char *abspath_to_file = NULL;
	char *archive_name = NULL;
	size_t archive_name_len = 0;
	char *symbol_store_path = NULL;
	char *dbg_file = NULL;
	char *guid = NULL;
	char *archive_name_escaped  = NULL;
	char *user_agent = NULL;
	char *symbol_server = NULL;

```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -18,150 +18,107 @@
 	return true;
 }
 
-static bool checkCurl() {
-	const char nul[] = R_SYS_DEVNULL;
-	if (r_sys_cmdf ("curl --version > %s", nul) != 0) {
-		return false;
-	}
+static bool download_and_write(SPDBDownloaderOpt *opt, const char *file) {
+	char *dir = r_str_newf ("%s%s%s%s%s",
+		opt->symbol_store_path, R_SYS_DIR,
+		opt->dbg_file, R_SYS_DIR,
+		opt->guid);
+	if (!r_sys_mkdirp (dir)) {
+		free (dir);
+		return false;
+	}
+	char *url = r_str_newf ("%s/%s/%s/%s", opt->symbol_server, opt->dbg_file, opt->guid, file);
+	int len;
+	char *file_buf = r_socket_http_get (url, NULL, &len);
+	free (url);
+	if (!len || R_STR_ISEMPTY (file_buf)) {
+		free (dir);
+		free (file_buf);
+		return false;
+	}
+	char *path = r_str_newf ("%s%s%s", dir, R_SYS_DIR, opt->dbg_file);
+	FILE *f = fopen (path, "wb");
+	if (f) {
+		fwrite (file_buf, sizeof (char), (size_t)len, f);
+		fclose (f);
+	}
+	free (dir);
+	free (path);
+	free (file_buf);
 	return true;
 }
 
 static int download(struct SPDBDownloader *pd) {
 	SPDBDownloaderOpt *opt = pd->opt;
-	char *curl_cmd = NULL;
-	char *extractor_cmd = NULL;
-	char *abspath_to_archive = NULL;
-	char *abspath_to_file = NULL;
-	char *archive_name = NULL;
-	size_t archive_name_len = 0;
-	char *symbol_store_path = NULL;
-	char *dbg_file = NULL;
-	char *guid = NULL;
-	char *archive_name_escaped  = NULL;
-	char *user_agent = NULL;
-	char *symbol_server = NULL;
-
 	int res = 0;
 	int cmd_ret;
+
 	if (!opt->dbg_file || !*opt->dbg_file) {
 		// no pdb debug file
 		return 0;
 	}
-	if (!checkCurl ()) {
-		return 0;
-	}
-	// dbg_file len is > 0
-	archive_name_len = strlen (opt->dbg_file);
-	archive_name = malloc (archive_name_len + 1);
-	if (!archive_name) {
-		return 0;
-	}
-	memcpy (archive_name, opt->dbg_file, archive_name_len + 1);
-	archive_name[archive_name_len - 1] = '_';
-	symbol_store_path = r_str_escape (opt->symbol_store_path);
-	dbg_file = r_str_escape (opt->dbg_file);
-	guid = r_str_escape (opt->guid);
-	archive_name_escaped = r_str_escape (archive_name);
-	user_agent = r_str_escape (opt->user_agent);
-	symbol_server = r_str_escape (opt->symbol_server);
-
-	abspath_to_archive = r_str_newf ("%s%s%s%s%s%s%s",
-			    symbol_store_path, R_SYS_DIR,
-			    dbg_file, R_SYS_DIR,
-			    guid, R_SYS_DIR,
-			    archive_name_escaped);
-
-	abspath_to_file = strdup (abspath_to_archive);
-	abspath_to_file[strlen (abspath_to_file) - 1] = 'b';
+
+	char *abspath_to_file = r_str_newf ("%s%s%s%s%s%s%s",
+		opt->symbol_store_path, R_SYS_DIR,
+		opt->dbg_file, R_SYS_DIR,
+		opt->guid, R_SYS_DIR,
+		opt->dbg_file);
+
 	if (r_file_exists (abspath_to_file)) {
 		eprintf ("File already downloaded.\n");
-		R_FREE (user_agent);
-		R_FREE (abspath_to_archive);
-		R_FREE (archive_name_escaped);
-		R_FREE (symbol_store_path);
-		R_FREE (dbg_file);
-		R_FREE (guid);
-		R_FREE (archive_name);
-		R_FREE (abspath_to_file);
-		R_FREE (symbol_server);
+		free (abspath_to_file);
 		return 1;
 	}
 
 	if (checkExtract () || opt->extract == 0) {
-		res = 1;
-
-		curl_cmd = r_str_newf ("curl -sfLA \"%s\" \"%s/%s/%s/%s\" --create-dirs -o \"%s\"",
-		                       user_agent,
-		                       symbol_server,
-							   dbg_file,
-							   guid,
-		                       archive_name_escaped,
-		                       abspath_to_archive);
+		char *extractor_cmd = NULL;
+		char *archive_name = strdup (opt->dbg_file);
+		archive_name[strlen (archive_name) - 1] = '_';
+		char *abspath_to_archive = r_str_newf ("%s%s%s%s%s%s%s",
+			opt->symbol_store_path, R_SYS_DIR,
+			opt->dbg_file, R_SYS_DIR,
+			opt->guid, R_SYS_DIR,
+			archive_name);
+
+		eprintf ("Attempting to download compressed pdb in %s\n", abspath_to_archive);
+		char *abs_arch_esc = r_str_escape_sh (abspath_to_archive);
 #if __WINDOWS__
-		const char *cabextractor = "expand";
-		const char *format = "%s %s %s";
-
-		// extractor_cmd -> %1 %2 %3
-		// %1 - 'expand'
-		// %2 - absolute path to archive
-		// %3 - absolute path to file that will be dearchive
-		extractor_cmd = r_str_newf (format, cabextractor,
-			abspath_to_archive, abspath_to_file);
+		char *abs_file_esc = r_str_escape_sh (abspath_to_file);
+		// expand %1 %2
+		// %1 - absolute path to archive
+		// %2 - absolute path to file that will be dearchive
+		extractor_cmd = r_str_newf ("expand \"%s\" \"%s\"", abs_arch_esc, abs_file_esc);
+		free (abs_file_esc);
 #else
-		const char *cabextractor = "cabextract";
-		const char *format = "%s -d \"%s\" \"%s\"";
 		char *abspath_to_dir = r_file_dirname (abspath_to_archive);
+		char *abs_dir_esc = r_str_escape_sh (abspath_to_dir);
 		// cabextract -d %1 %2
 		// %1 - path to directory where to extract all files from cab archive
 		// %2 - absolute path to cab archive
-		extractor_cmd = r_str_newf (format, cabextractor, abspath_to_dir, abspath_to_archive);
-		R_FREE (abspath_to_dir);
+		extractor_cmd = r_str_newf ("cabextract -d \"%s\" \"%s\"", abs_arch_esc, abs_dir_esc);
+		free (abs_dir_esc);
+		free (abspath_to_dir);
 #endif
-		eprintf ("Attempting to download compressed pdb in %s\n", abspath_to_archive);
-		if ((cmd_ret = r_sys_cmd (curl_cmd) != 0)) {
-			eprintf("curl exited with error %d\n", cmd_ret);
-			res = 0;
-		}
-		eprintf ("Attempting to decompress pdb\n");
-		if (opt->extract > 0) {
+		free (abs_arch_esc);
+		res = download_and_write (opt, archive_name);
+
+		if (opt->extract > 0 && res) {
+			eprintf ("Attempting to decompress pdb\n");
 			if (res && ((cmd_ret = r_sys_cmd (extractor_cmd)) != 0)) {
 				eprintf ("cab extractor exited with error %d\n", cmd_ret);
 				res = 0;
 			}
 			r_file_rm (abspath_to_archive);
 		}
-		R_FREE (curl_cmd);
+		free (archive_name);
+		free (abspath_to_archive);
 	}
 	if (res == 0) {
 		eprintf ("Falling back to uncompressed pdb\n");
-		res = 1;
-
-		archive_name_escaped[strlen (archive_name_escaped) - 1] = 'b';
-
-		curl_cmd = r_str_newf ("curl -sfLA \"%s\" \"%s/%s/%s/%s\" --create-dirs -o \"%s\"",
-		                       opt->user_agent,
-		                       opt->symbol_server,
-		                       opt->dbg_file,
-		                       opt->guid,
-		                       archive_name_escaped,
-		                       abspath_to_file);
 		eprintf ("Attempting to download uncompressed pdb in %s\n", abspath_to_file);
-		if ((cmd_ret = r_sys_cmd (curl_cmd) != 0)) {
-			eprintf("curl exited with error %d\n", cmd_ret);
-			res = 0;
-		}
-		R_FREE (curl_cmd);
-	}
-	R_FREE (abspath_to_archive);
-	R_FREE (abspath_to_file);
-	R_FREE (archive_name);
-	R_FREE (extractor_cmd);
-	R_FREE (symbol_store_path);
-	R_FREE (dbg_file);
-	R_FREE (guid);
-	R_FREE (archive_name_escaped);
-	R_FREE (user_agent);
-	R_FREE (symbol_server);
+		res = download_and_write (opt, opt->dbg_file);
+	}
+	free (abspath_to_file);
 	return res;
 }
 
@@ -191,6 +148,19 @@
 	pd->download = 0;
 }
 
+static bool is_valid_guid(const char *guid) {
+	if (!guid) {
+		return false;
+	}
+	size_t i;
+	for (i = 0; guid[i]; i++) {
+		if (!isxdigit (guid[i])) {
+			return false;
+		}
+	}
+	return i >= 33; // len of GUID and age
+}
+
 int r_bin_pdb_download(RCore *core, int isradjson, int *actions_done, SPDBOptions *options) {
 	int ret;
 	SPDBDownloaderOpt opt;
@@ -199,6 +169,11 @@
 
 	if (!info || !info->debug_file_name) {
 		eprintf ("Can't find debug filename\n");
+		return 1;
+	}
+
+	if (!is_valid_guid (info->guid)) {
+		eprintf ("Invalid GUID for file\n");
 		return 1;
 	}
 
```
