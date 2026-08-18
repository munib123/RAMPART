# CrossVul Fix Pair: Improper Privilege Management in cpp
**Pair ID:** 3234_4
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3234_4`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```cpp
Lines 280-320 of the vulnerable file.

	if( !dllHandle )
	{
		Com_Printf("Sys_UnloadDll(NULL)\n");
		return;
	}

	Sys_UnloadLibrary(dllHandle);
}

/*
=================
Sys_LoadDll

First try to load library name from system library path,
from executable path, then fs_basepath.
=================
*/
void *Sys_LoadDll( const char *name, qboolean useSystemLib )
{
	void *dllhandle = NULL;

	if ( useSystemLib )
	{
		Com_Printf( "Trying to load \"%s\"...\n", name );

		dllhandle = Sys_LoadLibrary( name );
		if ( dllhandle )
			return dllhandle;

		Com_Printf( "%s(%s) failed: \"%s\"\n", __FUNCTION__, name, Sys_LibraryError() );
	}

	const char *binarypath = Sys_BinaryPath();
	const char *basepath = Cvar_VariableString( "fs_basepath" );

	if ( !*binarypath )
		binarypath = ".";

	const char *searchPaths[] = {
		binarypath,
		basepath,
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -298,6 +298,13 @@
 {
 	void *dllhandle = NULL;
 
+	// Don't load any DLLs that end with the pk3 extension
+	if ( COM_CompareExtension( name, ".pk3" ) )
+	{
+		Com_Printf( S_COLOR_YELLOW "WARNING: Rejecting DLL named \"%s\"", name );
+		return NULL;
+	}
+
 	if ( useSystemLib )
 	{
 		Com_Printf( "Trying to load \"%s\"...\n", name );
```
