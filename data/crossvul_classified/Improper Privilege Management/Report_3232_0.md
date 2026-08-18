# CrossVul Fix Pair: Improper Privilege Management in c
**Pair ID:** 3232_0
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3232_0`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```c
Lines 2601-2641 of the vulnerable file.


	for (i = 0; i < MAX_RAW_STREAMS; i++) {
		streamSourceHandles[i] = -1;
		streamPlaying[i] = qfalse;
		streamSources[i] = 0;
		streamNumBuffers[i] = 0;
		streamBufIndex[i] = 0;
	}

	// New console variables
	s_alPrecache = Cvar_Get( "s_alPrecache", "1", CVAR_ARCHIVE );
	s_alGain = Cvar_Get( "s_alGain", "1.0", CVAR_ARCHIVE );
	s_alSources = Cvar_Get( "s_alSources", "128", CVAR_ARCHIVE );
	s_alDopplerFactor = Cvar_Get( "s_alDopplerFactor", "1.0", CVAR_ARCHIVE );
	s_alDopplerSpeed = Cvar_Get( "s_alDopplerSpeed", "9000", CVAR_ARCHIVE );
	s_alMinDistance = Cvar_Get( "s_alMinDistance", "120", CVAR_CHEAT );
	s_alMaxDistance = Cvar_Get("s_alMaxDistance", "1024", CVAR_CHEAT);
	s_alRolloff = Cvar_Get( "s_alRolloff", "2", CVAR_CHEAT);
	s_alGraceDistance = Cvar_Get("s_alGraceDistance", "512", CVAR_CHEAT);

	s_alDriver = Cvar_Get( "s_alDriver", ALDRIVER_DEFAULT, CVAR_ARCHIVE | CVAR_LATCH );

	s_alInputDevice = Cvar_Get( "s_alInputDevice", "", CVAR_ARCHIVE | CVAR_LATCH );
	s_alDevice = Cvar_Get("s_alDevice", "", CVAR_ARCHIVE | CVAR_LATCH);

	// Load QAL
	if( !QAL_Init( s_alDriver->string ) )
 	{
#if defined( _WIN32 )
		if( !Q_stricmp( s_alDriver->string, ALDRIVER_DEFAULT ) && !QAL_Init( "OpenAL64.dll" ) ) {
#elif defined ( __APPLE__ )
		if( !Q_stricmp( s_alDriver->string, ALDRIVER_DEFAULT ) && !QAL_Init( "/System/Library/Frameworks/OpenAL.framework/OpenAL" ) ) {
#else
		if( !Q_stricmp( s_alDriver->string, ALDRIVER_DEFAULT ) || !QAL_Init( ALDRIVER_DEFAULT ) ) {
#endif
			return qfalse;
		}
 	}

	device = s_alDevice->string;
	if(device && !*device)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2618,10 +2618,16 @@
 	s_alRolloff = Cvar_Get( "s_alRolloff", "2", CVAR_CHEAT);
 	s_alGraceDistance = Cvar_Get("s_alGraceDistance", "512", CVAR_CHEAT);
 
-	s_alDriver = Cvar_Get( "s_alDriver", ALDRIVER_DEFAULT, CVAR_ARCHIVE | CVAR_LATCH );
+	s_alDriver = Cvar_Get( "s_alDriver", ALDRIVER_DEFAULT, CVAR_ARCHIVE | CVAR_LATCH | CVAR_PROTECTED );
 
 	s_alInputDevice = Cvar_Get( "s_alInputDevice", "", CVAR_ARCHIVE | CVAR_LATCH );
 	s_alDevice = Cvar_Get("s_alDevice", "", CVAR_ARCHIVE | CVAR_LATCH);
+
+	if ( COM_CompareExtension( s_alDriver->string, ".pk3" ) )
+	{
+		Com_Printf( "Rejecting DLL named \"%s\"", s_alDriver->string );
+		return qfalse;
+	}
 
 	// Load QAL
 	if( !QAL_Init( s_alDriver->string ) )
```
