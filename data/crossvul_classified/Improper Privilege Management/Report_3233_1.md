# CrossVul Fix Pair: Improper Privilege Management in c
**Pair ID:** 3233_1
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3233_1`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```c
Lines 1407-1447 of the vulnerable file.

	}

	*file = 0;
	return -1;
}

/*
===========
FS_FOpenFileRead

Finds the file in the search path.
Returns filesize and an open FILE pointer.
Used for streaming data out of either a
separate file or a ZIP file.
===========
*/
long FS_FOpenFileRead(const char *filename, fileHandle_t *file, qboolean uniqueFILE)
{
	searchpath_t *search;
	long len;

	if(!fs_searchpaths)
		Com_Error(ERR_FATAL, "Filesystem call made without initialization");

	for(search = fs_searchpaths; search; search = search->next)
	{
	        len = FS_FOpenFileReadDir(filename, search, file, uniqueFILE, qfalse);
	        
	        if(file == NULL)
	        {
	                if(len > 0)
	                        return len;
	        }
	        else
	        {
	                if(len >= 0 && *file)
	                        return len;
	        }
	        
	}
	
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1424,12 +1424,18 @@
 {
 	searchpath_t *search;
 	long len;
+	qboolean isLocalConfig;
 
 	if(!fs_searchpaths)
 		Com_Error(ERR_FATAL, "Filesystem call made without initialization");
 
+	isLocalConfig = !strcmp(filename, "autoexec.cfg") || !strcmp(filename, Q3CONFIG_CFG);
 	for(search = fs_searchpaths; search; search = search->next)
 	{
+		// autoexec.cfg and wolfconfig_mp.cfg can only be loaded outside of pk3 files.
+		if (isLocalConfig && search->pack)
+			continue;
+
 	        len = FS_FOpenFileReadDir(filename, search, file, uniqueFILE, qfalse);
 	        
 	        if(file == NULL)
```
