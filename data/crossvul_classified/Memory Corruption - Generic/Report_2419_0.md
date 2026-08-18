# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2419_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2419_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 2793-2833 of the vulnerable file.


static void
main_get_appheader (xd3_stream *stream, main_file *ifile,
		    main_file *output, main_file *sfile)
{
  uint8_t *apphead;
  usize_t appheadsz;
  int ret;

  /* The user may disable the application header.  Once the appheader
   * is set, this disables setting it again. */
  if (! option_use_appheader) { return; }

  ret = xd3_get_appheader (stream, & apphead, & appheadsz);

  /* Ignore failure, it only means we haven't received a header yet. */
  if (ret != 0) { return; }

  if (appheadsz > 0)
    {
      char *start = (char*)apphead;
      char *slash;
      int   place = 0;
      char *parsed[4];

      memset (parsed, 0, sizeof (parsed));

      while ((slash = strchr (start, '/')) != NULL)
	{
	  *slash = 0;
	  parsed[place++] = start;
	  start = slash + 1;
	}

      parsed[place++] = start;

      /* First take the output parameters. */
      if (place == 2 || place == 4)
	{
	  main_get_appheader_params (output, parsed, 1, "output", ifile);
	}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -2810,14 +2810,15 @@
 
   if (appheadsz > 0)
     {
+      const int kMaxArgs = 4;
       char *start = (char*)apphead;
       char *slash;
       int   place = 0;
-      char *parsed[4];
+      char *parsed[kMaxArgs];
 
       memset (parsed, 0, sizeof (parsed));
 
-      while ((slash = strchr (start, '/')) != NULL)
+      while ((slash = strchr (start, '/')) != NULL && place < (kMaxArgs-1))
 	{
 	  *slash = 0;
 	  parsed[place++] = start;
```
