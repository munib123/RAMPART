# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 4074_1
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4074_1`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 13-53 of the vulnerable file.

/*---------------------------------------------------------------------------
                                Includes
 ---------------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * The following #include is necessary on many Unixes but not Linux.
 * It is not needed for Windows platforms.
 * Uncomment it if needed.
 */
/* #include <unistd.h> */

#include "dictionary.h"

#ifdef __cplusplus
extern "C" {
#endif

/*-------------------------------------------------------------------------*/
/**
  @brief    Get number of sections in a dictionary
  @param    d   Dictionary to examine
  @return   int Number of sections found in dictionary

  This function returns the number of sections found in a dictionary.
  The test to recognize sections is done on the string stored in the
  dictionary: a section name is given as "section" whereas a key is
  stored as "section:key", thus the test looks for entries that do not
  contain a colon.

  This clearly fails in the case a section name contains a colon, but
  this should simply be avoided.

  This function returns -1 in case of error.
 */
/*--------------------------------------------------------------------------*/

int iniparser_getnsec(const dictionary * d);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -30,6 +30,10 @@
 #ifdef __cplusplus
 extern "C" {
 #endif
+
+typedef enum {
+  HIDE_ERRORED_LINE_CONTENT = (1<<0)
+} load_options;
 
 /*-------------------------------------------------------------------------*/
 /**
@@ -286,6 +290,7 @@
 /**
   @brief    Parse an ini file and return an allocated dictionary object
   @param    ininame Name of the ini file to read.
+  @param    options Name of the ini file to read.
   @return   Pointer to newly allocated dictionary
 
   This is the parser for ini files. This function is called, providing
@@ -296,7 +301,7 @@
   The returned dictionary must be freed using iniparser_freedict().
  */
 /*--------------------------------------------------------------------------*/
-dictionary * iniparser_load(const char * ininame);
+dictionary * iniparser_load(const char * ininame, load_options options);
 
 /*-------------------------------------------------------------------------*/
 /**
```
