# CrossVul Fix Pair: Improper Privilege Management in c
**Pair ID:** 3231_0
**Vulnerability Class:** Improper Privilege Management
**CWE:** CWE-269
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3231_0`)

## Vulnerability Information & PoC

## Description
Improper Privilege Management - The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.

## Vulnerable Code
```c
Lines 209-249 of the vulnerable file.

Con_Dump_f

Save the console contents out to a file
================
*/
void Con_Dump_f( void ) {
	int l, x, i;
	short   *line;
	fileHandle_t f;
	int		bufferlen;
	char	*buffer;
	char	filename[MAX_QPATH];

	if ( Cmd_Argc() != 2 ) {
		Com_Printf( "usage: condump <filename>\n" );
		return;
	}

	Q_strncpyz( filename, Cmd_Argv( 1 ), sizeof( filename ) );
	COM_DefaultExtension( filename, sizeof( filename ), ".txt" );

	f = FS_FOpenFileWrite( filename );
	if ( !f ) {
		Com_Printf ("ERROR: couldn't open %s.\n", filename);
		return;
	}

	Com_Printf ("Dumped console text to %s.\n", filename );

	// skip empty lines
	for ( l = con.current - con.totallines + 1 ; l <= con.current ; l++ )
	{
		line = con.text + ( l % con.totallines ) * con.linewidth;
		for ( x = 0 ; x < con.linewidth ; x++ )
			if ( ( line[x] & 0xff ) != ' ' ) {
				break;
			}
		if ( x != con.linewidth ) {
			break;
		}
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -226,6 +226,12 @@
 
 	Q_strncpyz( filename, Cmd_Argv( 1 ), sizeof( filename ) );
 	COM_DefaultExtension( filename, sizeof( filename ), ".txt" );
+
+	if (!COM_CompareExtension(filename, ".txt"))
+	{
+		Com_Printf("Con_Dump_f: Only the \".txt\" extension is supported by this command!\n");
+		return;
+	}
 
 	f = FS_FOpenFileWrite( filename );
 	if ( !f ) {
```
