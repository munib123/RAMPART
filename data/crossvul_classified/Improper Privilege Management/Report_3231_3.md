# CrossVul Fix Pair: Improper Privilege Management in c
**Pair ID:** 3231_3
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3231_3`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```c
Lines 2584-2624 of the vulnerable file.

	}
#endif
}


/*
===============
Com_WriteConfig_f

Write the config file to a specific name
===============
*/
void Com_WriteConfig_f( void ) {
	char filename[MAX_QPATH];

	if ( Cmd_Argc() != 2 ) {
		Com_Printf( "Usage: writeconfig <filename>\n" );
		return;
	}

	Q_strncpyz( filename, Cmd_Argv( 1 ), sizeof( filename ) );
	COM_DefaultExtension( filename, sizeof( filename ), ".cfg" );
	Com_Printf( "Writing %s.\n", filename );
	Com_WriteConfigToFile( filename );
}

/*
================
Com_ModifyMsec
================
*/
int Com_ModifyMsec( int msec ) {
	int clampTime;

	//
	// modify time for debugging values
	//
	if ( com_fixedtime->integer ) {
		msec = com_fixedtime->integer;
	} else if ( com_timescale->value ) {
		msec *= com_timescale->value;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2601,6 +2601,12 @@
 		return;
 	}
 
+	if (!COM_CompareExtension(filename, ".cfg"))
+	{
+		Com_Printf("Com_WriteConfig_f: Only the \".cfg\" extension is supported by this command!\n");
+		return;
+	}
+
 	Q_strncpyz( filename, Cmd_Argv( 1 ), sizeof( filename ) );
 	COM_DefaultExtension( filename, sizeof( filename ), ".cfg" );
 	Com_Printf( "Writing %s.\n", filename );
```
