# CrossVul Fix Pair: Improper Privilege Management in cpp
**Pair ID:** 3234_2
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** cpp
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3234_2`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```cpp
Lines 2347-2387 of the vulnerable file.

static void CM_SetUsingCache( qboolean usingCache ) { gbUsingCachedMapDataRightNow = usingCache; }

#define G2_VERT_SPACE_SERVER_SIZE 256
IHeapAllocator *G2VertSpaceServer = NULL;
CMiniHeap IHeapAllocator_singleton(G2_VERT_SPACE_SERVER_SIZE * 1024);

static IHeapAllocator *GetG2VertSpaceServer( void ) {
	return G2VertSpaceServer;
}

#define DEFAULT_RENDER_LIBRARY "rd-vanilla"

void CL_InitRef( void ) {
	static refimport_t ri;
	refexport_t	*ret;
	GetRefAPI_t	GetRefAPI;
	char		dllName[MAX_OSPATH];

	Com_Printf( "----- Initializing Renderer ----\n" );

	cl_renderer = Cvar_Get( "cl_renderer", DEFAULT_RENDER_LIBRARY, CVAR_ARCHIVE|CVAR_LATCH, "Which renderer library to use" );

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

	memset( &ri, 0, sizeof( ri ) );

	GetRefAPI = (GetRefAPI_t)Sys_LoadFunction( rendererLib, "GetRefAPI" );
	if ( !GetRefAPI )
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2364,7 +2364,7 @@
 
 	Com_Printf( "----- Initializing Renderer ----\n" );
 
-	cl_renderer = Cvar_Get( "cl_renderer", DEFAULT_RENDER_LIBRARY, CVAR_ARCHIVE|CVAR_LATCH, "Which renderer library to use" );
+	cl_renderer = Cvar_Get( "cl_renderer", DEFAULT_RENDER_LIBRARY, CVAR_ARCHIVE|CVAR_LATCH|CVAR_PROTECTED, "Which renderer library to use" );
 
 	Com_sprintf( dllName, sizeof( dllName ), "%s_" ARCH_STRING DLL_EXT, cl_renderer->string );
 
```
