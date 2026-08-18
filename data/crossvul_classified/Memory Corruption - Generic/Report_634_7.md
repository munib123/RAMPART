# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 634_7
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `634_7`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 4-44 of the vulnerable file.

 * This code was created by Peter Harvey @ CodeByDesign.
 * Released under LGPL 28.JAN.99
 *
 * Contributions from...
 * -----------------------------------------------
 * Peter Harvey		- pharvey@codebydesign.com
 **************************************************/
#include <config.h>
#include <odbcinstext.h>

BOOL SQLWriteFileDSN(			LPCSTR	pszFileName,
								LPCSTR	pszAppName,
								LPCSTR	pszKeyName,
								LPCSTR	pszString )
{
	HINI	hIni;
	char	szFileName[ODBC_FILENAME_MAX+1];

	if ( pszFileName[0] == '/' )
	{
		strncpy( szFileName, sizeof(szFileName) - 5, pszFileName );
	}
	else
	{	
		char szPath[ODBC_FILENAME_MAX+1];
		*szPath = '\0';
		_odbcinst_FileINI( szPath );
		snprintf( szFileName, sizeof(szFileName) - 5, "%s/%s", szPath, pszFileName );
	}

    if ( strlen( szFileName ) < 4 || strcmp( szFileName + strlen( szFileName ) - 4, ".dsn" ))
    {
        strcat( szFileName, ".dsn" );
    }

#ifdef __OS2__
	if ( iniOpen( &hIni, szFileName, "#;", '[', ']', '=', TRUE, 0L ) != INI_SUCCESS )
#else
	if ( iniOpen( &hIni, szFileName, "#;", '[', ']', '=', TRUE ) != INI_SUCCESS )
#endif
	{
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -21,7 +21,7 @@
 
 	if ( pszFileName[0] == '/' )
 	{
-		strncpy( szFileName, sizeof(szFileName) - 5, pszFileName );
+		strncpy( szFileName, pszFileName, sizeof(szFileName) - 5 );
 	}
 	else
 	{	
```
