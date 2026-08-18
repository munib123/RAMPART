# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 5096_1
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5096_1`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 101-144 of the vulnerable file.

      }

  if (opj_optind != argc)
    {
    for (index = opj_optind; index < argc; index++)
      fprintf(stderr,"Non-option argument %s\n", argv[index]);
    return 1;
    }

  return 0;
}

/*******************************************************************************
 * MAIN
 *******************************************************************************/
int main(int argc, char **argv)
{
  test_cmp_parameters inParam;
  FILE *fbase=NULL, *ftest=NULL;
  int same = 0;
  char lbase[256];
  char strbase[256];
  char ltest[256];
  char strtest[256];

  if( parse_cmdline_cmp(argc, argv, &inParam) == 1 )
    {
    compare_dump_files_help_display();
    goto cleanup;
    }

  /* Display Parameters*/
  printf("******Parameters********* \n");
  printf(" base_filename = %s\n"
    " test_filename = %s\n",
    inParam.base_filename, inParam.test_filename);
  printf("************************* \n");

  /* open base file */
  printf("Try to open: %s for reading ... ", inParam.base_filename);
  if((fbase = fopen(inParam.base_filename, "rb"))==NULL)
    {
    goto cleanup;
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -118,10 +118,10 @@
   test_cmp_parameters inParam;
   FILE *fbase=NULL, *ftest=NULL;
   int same = 0;
-  char lbase[256];
-  char strbase[256];
-  char ltest[256];
-  char strtest[256];
+  char lbase[512];
+  char strbase[512];
+  char ltest[512];
+  char strtest[512];
 
   if( parse_cmdline_cmp(argc, argv, &inParam) == 1 )
     {
@@ -154,9 +154,9 @@
 
   while (fgets(lbase, sizeof(lbase), fbase) && fgets(ltest,sizeof(ltest),ftest))
     {
-    int nbase = sscanf(lbase, "%255[^\r\n]", strbase);
-    int ntest = sscanf(ltest, "%255[^\r\n]", strtest);
-    assert( nbase != 255 && ntest != 255 );
+    int nbase = sscanf(lbase, "%511[^\r\n]", strbase);
+    int ntest = sscanf(ltest, "%511[^\r\n]", strtest);
+    assert( nbase != 511 && ntest != 511 );
     if( nbase != 1 || ntest != 1 )
       {
       fprintf(stderr, "could not parse line from files\n" );
```
