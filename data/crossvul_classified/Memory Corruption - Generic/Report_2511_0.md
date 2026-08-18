# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2511_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2511_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 413-472 of the vulnerable file.


 fail:
	gluster_free_server(hosts);
	return NULL;
}

static char* tcmu_get_path( struct tcmu_device *dev)
{
	char *config;

	config = strchr(tcmu_get_dev_cfgstring(dev), '/');
	if (!config) {
		tcmu_err("no configuration found in cfgstring\n");
		return NULL;
	}
	config += 1; /* get past '/' */

	return config;
}


static bool glfs_check_config(const char *cfgstring, char **reason)
{
	char *path;
	glfs_t *fs = NULL;
	glfs_fd_t *gfd = NULL;
	gluster_server *hosts = NULL; /* gluster server defination */
	bool result = true;

	path = strchr(cfgstring, '/');
	if (!path) {
		if (asprintf(reason, "No path found") == -1)
			*reason = NULL;
		result = false;
		goto done;
	}
	path += 1; /* get past '/' */

	fs = tcmu_create_glfs_object(path, &hosts);
	if (!fs) {
		tcmu_err("tcmu_create_glfs_object failed\n");
		goto done;
	}

	gfd = glfs_open(fs, hosts->path, ALLOWED_BSOFLAGS);
	if (!gfd) {
		if (asprintf(reason, "glfs_open failed: %m") == -1)
			*reason = NULL;
		result = false;
		goto unref;
	}

	if (glfs_access(fs, hosts->path, R_OK|W_OK) == -1) {
		if (asprintf(reason, "glfs_access file not present, or not writable") == -1)
			*reason = NULL;
		result = false;
		goto unref;
	}

	goto done;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -430,58 +430,6 @@
 	return config;
 }
 
-
-static bool glfs_check_config(const char *cfgstring, char **reason)
-{
-	char *path;
-	glfs_t *fs = NULL;
-	glfs_fd_t *gfd = NULL;
-	gluster_server *hosts = NULL; /* gluster server defination */
-	bool result = true;
-
-	path = strchr(cfgstring, '/');
-	if (!path) {
-		if (asprintf(reason, "No path found") == -1)
-			*reason = NULL;
-		result = false;
-		goto done;
-	}
-	path += 1; /* get past '/' */
-
-	fs = tcmu_create_glfs_object(path, &hosts);
-	if (!fs) {
-		tcmu_err("tcmu_create_glfs_object failed\n");
-		goto done;
-	}
-
-	gfd = glfs_open(fs, hosts->path, ALLOWED_BSOFLAGS);
-	if (!gfd) {
-		if (asprintf(reason, "glfs_open failed: %m") == -1)
-			*reason = NULL;
-		result = false;
-		goto unref;
-	}
-
-	if (glfs_access(fs, hosts->path, R_OK|W_OK) == -1) {
-		if (asprintf(reason, "glfs_access file not present, or not writable") == -1)
-			*reason = NULL;
-		result = false;
-		goto unref;
-	}
-
-	goto done;
-
-unref:
-	gluster_cache_refresh(fs, path);
-
-done:
-	if (gfd)
-		glfs_close(gfd);
-	gluster_free_server(&hosts);
-
-	return result;
-}
-
 static int tcmu_glfs_open(struct tcmu_device *dev)
 {
 	struct glfs_state *gfsp;
@@ -681,8 +629,6 @@
 	.subtype 	= "glfs",
 	.cfg_desc	= glfs_cfg_desc,
 
-	.check_config 	= glfs_check_config,
-
 	.open 		= tcmu_glfs_open,
 	.close 		= tcmu_glfs_close,
 	.read 		= tcmu_glfs_read,
```
