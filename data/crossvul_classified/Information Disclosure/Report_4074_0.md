# CrossVul Fix Pair: Exposure of Sensitive Information to an Unauthorized Actor in c
**Pair ID:** 4074_0
**Vulnerability Class:** Information Disclosure
**CWE:** CWE-200
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4074_0`)

## Vulnerability Information & PoC

## Description
Exposure of Sensitive Information to an Unauthorized Actor - There are many different kinds of mistakes that introduce information exposures.

## Vulnerable Code
```c
Lines 609-649 of the vulnerable file.

    }

    free(line);
    return sta ;
}

/*-------------------------------------------------------------------------*/
/**
  @brief    Parse an ini file and return an allocated dictionary object
  @param    ininame Name of the ini file to read.
  @return   Pointer to newly allocated dictionary

  This is the parser for ini files. This function is called, providing
  the name of the file to be read. It returns a dictionary object that
  should not be accessed directly, but through accessor functions
  instead.

  The returned dictionary must be freed using iniparser_freedict().
 */
/*--------------------------------------------------------------------------*/
dictionary * iniparser_load(const char * ininame)
{
    FILE * in ;

    char line    [ASCIILINESZ+1] ;
    char section [ASCIILINESZ+1] ;
    char key     [ASCIILINESZ+1] ;
    char tmp     [(ASCIILINESZ * 2) + 1] ;
    char val     [ASCIILINESZ+1] ;

    int  last=0 ;
    int  len ;
    int  lineno=0 ;
    int  errs=0;

    dictionary * dict ;

    if ((in=fopen(ininame, "r"))==NULL) {
        fprintf(stderr, "iniparser: cannot open %s\n", ininame);
        return NULL ;
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -626,7 +626,7 @@
   The returned dictionary must be freed using iniparser_freedict().
  */
 /*--------------------------------------------------------------------------*/
-dictionary * iniparser_load(const char * ininame)
+dictionary * iniparser_load(const char * ininame, load_options options)
 {
     FILE * in ;
 
@@ -707,10 +707,18 @@
             break ;
 
             case LINE_ERROR:
-            fprintf(stderr, "iniparser: syntax error in %s (%d):\n",
-                    ininame,
-                    lineno);
-            fprintf(stderr, "-> %s\n", line);
+
+            if(options & HIDE_ERRORED_LINE_CONTENT) {
+              fprintf(stderr, "iniparser: syntax error in %s (%d)\n",
+                      ininame,
+                      lineno);
+            }
+            else {
+              fprintf(stderr, "iniparser: syntax error in %s (%d):\n",
+                      ininame,
+                      lineno);
+              fprintf(stderr, "-> %s\n", line);
+            }
             errs++ ;
             break;
 
```
