# CrossVul Fix Pair: Improper Privilege Management in cpp
**Pair ID:** 3234_0
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3234_0`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```cpp
Lines 1067-1107 of the vulnerable file.

extern cvar_t *Cvar_Set2( const char *var_name, const char *value, qboolean force);
extern CMiniHeap *G2VertSpaceServer;
static CMiniHeap *GetG2VertSpaceServer( void ) {
	return G2VertSpaceServer;
}

// NOTENOTE: If you change the output name of rd-vanilla, change this define too!
#ifdef JK2_MODE
#define DEFAULT_RENDER_LIBRARY	"rdjosp-vanilla"
#else
#define DEFAULT_RENDER_LIBRARY	"rdsp-vanilla"
#endif

void CL_InitRef( void ) {
	refexport_t	*ret;
	static refimport_t rit;
	char		dllName[MAX_OSPATH];
	GetRefAPI_t	GetRefAPI;

	Com_Printf( "----- Initializing Renderer ----\n" );
    cl_renderer = Cvar_Get( "cl_renderer", DEFAULT_RENDER_LIBRARY, CVAR_ARCHIVE|CVAR_LATCH );

	Com_sprintf( dllName, sizeof( dllName ), "%s_" ARCH_STRING DLL_EXT, cl_renderer->string );

	if( !(rendererLib = Sys_LoadDll( dllName, qfalse )) && strcmp( cl_renderer->string, cl_renderer->resetString ) )
	{
		Com_Printf( "failed: trying to load fallback renderer\n" );
		Cvar_ForceReset( "cl_renderer" );

		Com_sprintf( dllName, sizeof( dllName ), DEFAULT_RENDER_LIBRARY "_" ARCH_STRING DLL_EXT );
		rendererLib = Sys_LoadDll( dllName, qfalse );
	}

	if ( !rendererLib ) {
		Com_Error( ERR_FATAL, "Failed to load renderer\n" );
	}

	memset( &rit, 0, sizeof( rit ) );

	GetRefAPI = (GetRefAPI_t)Sys_LoadFunction( rendererLib, "GetRefAPI" );
	if ( !GetRefAPI )
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1084,7 +1084,7 @@
 	GetRefAPI_t	GetRefAPI;
 
 	Com_Printf( "----- Initializing Renderer ----\n" );
-    cl_renderer = Cvar_Get( "cl_renderer", DEFAULT_RENDER_LIBRARY, CVAR_ARCHIVE|CVAR_LATCH );
+    cl_renderer = Cvar_Get( "cl_renderer", DEFAULT_RENDER_LIBRARY, CVAR_ARCHIVE|CVAR_LATCH|CVAR_PROTECTED );
 
 	Com_sprintf( dllName, sizeof( dllName ), "%s_" ARCH_STRING DLL_EXT, cl_renderer->string );
 
```
