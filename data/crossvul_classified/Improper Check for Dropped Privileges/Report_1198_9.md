# CrossVul Fix Pair: Improper Check for Dropped Privileges in c
**Pair ID:** 1198_9
**Vulnerability Class:** Improper Check for Dropped Privileges
**CWE:** CWE-273
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1198_9`)

## Vulnerability Information & PoC

## Description
Improper Check for Dropped Privileges - If the drop fails, the product will continue to run with the raised privileges, which might provide additional access to unprivileged users.

## Vulnerable Code
```c
Lines 617-657 of the vulnerable file.

   Return -1 if cannot access directory DIR.
   Look in errno for more information.  */

char **
glob_vector (pat, dir, flags)
     char *pat;
     char *dir;
     int flags;
{
  DIR *d;
  register struct dirent *dp;
  struct globval *lastlink, *e, *dirlist;
  register struct globval *nextlink;
  register char *nextname, *npat, *subdir;
  unsigned int count;
  int lose, skip, ndirs, isdir, sdlen, add_current, patlen;
  register char **name_vector;
  register unsigned int i;
  int mflags;		/* Flags passed to strmatch (). */
  int pflags;		/* flags passed to sh_makepath () */
  int nalloca;
  struct globval *firstmalloc, *tmplink;
  char *convfn;

  lastlink = 0;
  count = lose = skip = add_current = 0;

  firstmalloc = 0;
  nalloca = 0;

  name_vector = NULL;

/*itrace("glob_vector: pat = `%s' dir = `%s' flags = 0x%x", pat, dir, flags);*/
  /* If PAT is empty, skip the loop, but return one (empty) filename. */
  if (pat == 0 || *pat == '\0')
    {
      if (glob_testdir (dir, 0) < 0)
	return ((char **) &glob_error_return);

      nextlink = (struct globval *)alloca (sizeof (struct globval));
      if (nextlink == NULL)
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -634,6 +634,7 @@
   register unsigned int i;
   int mflags;		/* Flags passed to strmatch (). */
   int pflags;		/* flags passed to sh_makepath () */
+  int hasglob;		/* return value from glob_pattern_p */
   int nalloca;
   struct globval *firstmalloc, *tmplink;
   char *convfn;
@@ -675,10 +676,12 @@
   patlen = (pat && *pat) ? strlen (pat) : 0;
 
   /* If the filename pattern (PAT) does not contain any globbing characters,
+     or contains a pattern with only backslash escapes (hasglob == 2),
      we can dispense with reading the directory, and just see if there is
      a filename `DIR/PAT'.  If there is, and we can access it, just make the
      vector to return and bail immediately. */
-  if (skip == 0 && glob_pattern_p (pat) == 0)
+  hasglob = 0;
+  if (skip == 0 && (hasglob = glob_pattern_p (pat)) == 0 || hasglob == 2)
     {
       int dirlen;
       struct stat finfo;
```
