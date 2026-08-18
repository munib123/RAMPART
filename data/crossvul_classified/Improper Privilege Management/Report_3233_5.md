# CrossVul Fix Pair: Improper Privilege Management in c
**Pair ID:** 3233_5
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3233_5`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```c
Lines 482-522 of the vulnerable file.

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

void *Sys_LoadDll(const char *name, qboolean useSystemLib)
{
	void *dllhandle;
	
	if(useSystemLib)
		Com_Printf("Trying to load \"%s\"...\n", name);
	
	if(!useSystemLib || !(dllhandle = Sys_LoadLibrary(name)))
	{
		const char *topDir;
		char libPath[MAX_OSPATH];

		topDir = Sys_BinaryPath();

		if(!*topDir)
			topDir = ".";

		Com_Printf("Trying to load \"%s\" from \"%s\"...\n", name, topDir);
		Com_sprintf(libPath, sizeof(libPath), "%s%c%s", topDir, PATH_SEP, name);

		if(!(dllhandle = Sys_LoadLibrary(libPath)))
		{
			const char *basePath = Cvar_VariableString("fs_basepath");
			
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -499,6 +499,13 @@
 void *Sys_LoadDll(const char *name, qboolean useSystemLib)
 {
 	void *dllhandle;
+
+	// Don't load any DLLs that end with the pk3 extension
+	if (COM_CompareExtension(name, ".pk3"))
+	{
+		Com_Printf("Rejecting DLL named \"%s\"", name);
+		return NULL;
+	}
 	
 	if(useSystemLib)
 		Com_Printf("Trying to load \"%s\"...\n", name);
```
