# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 3407_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3407_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 74-116 of the vulnerable file.

       (! (filetype & GRUB_FSHELP_CASE_INSENSITIVE) ||
	grub_strncasecmp (c->name, filename, GRUB_LONG_MAX))))
    {
      grub_free (node);
      return 0;
    }

  /* The node is found, stop iterating over the nodes.  */
  *(c->type) = filetype & ~GRUB_FSHELP_CASE_INSENSITIVE;
  *(c->oldnode) = *(c->currnode);
  *(c->currnode) = node;

  return 1;
}

static grub_err_t
find_file (const char *currpath, grub_fshelp_node_t currroot,
	   grub_fshelp_node_t *currfound,
	   struct grub_fshelp_find_file_closure *c)
{
#ifndef _MSC_VER
	char fpath[grub_strlen (currpath) + 1];
#else
	char *fpath = grub_malloc (grub_strlen (currpath) + 1);
#endif
  char *name = fpath;
  char *next;
  enum grub_fshelp_filetype type = GRUB_FSHELP_DIR;
  grub_fshelp_node_t currnode = currroot;
  grub_fshelp_node_t oldnode = currroot;

  c->currroot = currroot;

  grub_strncpy (fpath, currpath, grub_strlen (currpath) + 1);

  /* Remove all leading slashes.  */
  while (*name == '/')
    name++;

  if (! *name)
    {
      *currfound = currnode;
      return 0;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -91,11 +91,7 @@
 	   grub_fshelp_node_t *currfound,
 	   struct grub_fshelp_find_file_closure *c)
 {
-#ifndef _MSC_VER
-	char fpath[grub_strlen (currpath) + 1];
-#else
 	char *fpath = grub_malloc (grub_strlen (currpath) + 1);
-#endif
   char *name = fpath;
   char *next;
   enum grub_fshelp_filetype type = GRUB_FSHELP_DIR;
@@ -113,6 +109,7 @@
   if (! *name)
     {
       *currfound = currnode;
+free (fpath);
       return 0;
     }
 
@@ -135,6 +132,7 @@
       if (type != GRUB_FSHELP_DIR)
 	{
 	  free_node (currnode, c);
+free (fpath);
 	  return grub_error (GRUB_ERR_BAD_FILE_TYPE, "not a directory");
 	}
 
@@ -146,8 +144,10 @@
       found = c->iterate_dir (currnode, iterate, &cc);
       if (! found)
 	{
-	  if (grub_errno)
+	  if (grub_errno) {
+free (fpath);
 	    return grub_errno;
+}
 
 	  break;
 	}
@@ -162,6 +162,7 @@
 	    {
 	      free_node (currnode, c);
 	      free_node (oldnode, c);
+free (fpath);
 	      return grub_error (GRUB_ERR_SYMLINK_LOOP,
 				 "too deep nesting of symlinks");
 	    }
@@ -172,6 +173,7 @@
 	  if (!symlink)
 	    {
 	      free_node (oldnode, c);
+free (fpath);
 	      return grub_errno;
 	    }
 
@@ -190,6 +192,7 @@
 	  if (grub_errno)
 	    {
 	      free_node (oldnode, c);
+free (fpath);
 	      return grub_errno;
 	    }
 	}
@@ -201,12 +204,14 @@
 	{
 	  *currfound = currnode;
 	  c->foundtype = type;
+free (fpath);
 	  return 0;
 	}
 
       name = next;
     }
 
+free (fpath);
   return grub_error (GRUB_ERR_FILE_NOT_FOUND, "file not found");
 }
 
```
