# CrossVul Fix Pair: Improper Privilege Management in cpp
**Pair ID:** 3234_3
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3234_3`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```cpp
Lines 1250-1290 of the vulnerable file.

FS_FOpenFileRead

Finds the file in the search path.
Returns filesize and an open FILE pointer.
Used for streaming data out of either a
separate file or a ZIP file.
===========
*/
extern qboolean		com_fullyInitialized;

long FS_FOpenFileRead( const char *filename, fileHandle_t *file, qboolean uniqueFILE ) {
	searchpath_t	*search;
	char			*netpath;
	pack_t			*pak;
	fileInPack_t	*pakFile;
	directory_t		*dir;
	long			hash;
	//unz_s			*zfi;
	//void			*temp;
	int				l;

	hash = 0;

	FS_AssertInitialised();

	if ( file == NULL ) {
		Com_Error( ERR_FATAL, "FS_FOpenFileRead: NULL 'file' parameter passed\n" );
	}

	if ( !filename ) {
		Com_Error( ERR_FATAL, "FS_FOpenFileRead: NULL 'filename' parameter passed\n" );
	}

	// qpaths are not supposed to have a leading slash
	if ( filename[0] == '/' || filename[0] == '\\' ) {
		filename++;
	}

	// make absolutely sure that it can't back up the path.
	// The searchpaths do guarantee that something will always
	// be prepended, so we don't need to worry about "c:" or "//limbo"
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1267,6 +1267,7 @@
 	//unz_s			*zfi;
 	//void			*temp;
 	int				l;
+	bool			isUserConfig = false;
 
 	hash = 0;
 
@@ -1299,6 +1300,8 @@
 		*file = 0;
 		return -1;
 	}
+
+	isUserConfig = !Q_stricmp( filename, "autoexec.cfg" ) || !Q_stricmp( filename, Q3CONFIG_CFG );
 
 	//
 	// search through the path, one element at a time
@@ -1327,6 +1330,11 @@
 			if ( search->pack && search->pack->hashTable[hash] ) {
 				// disregard if it doesn't match one of the allowed pure pak files
 				if ( !FS_PakIsPure(search->pack) ) {
+					continue;
+				}
+
+				// autoexec.cfg and openjk.cfg can only be loaded outside of pk3 files.
+				if ( isUserConfig ) {
 					continue;
 				}
 
```
