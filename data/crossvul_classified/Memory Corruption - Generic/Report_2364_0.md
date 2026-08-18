# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 2364_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2364_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 86-126 of the vulnerable file.

  h->filename = strdup (filename);
  if (h->filename == NULL)
    goto error;

#ifdef O_CLOEXEC
  h->fd = open (filename, O_RDONLY | O_CLOEXEC | O_BINARY);
#else
  h->fd = open (filename, O_RDONLY | O_BINARY);
#endif
  if (h->fd == -1)
    goto error;
#ifndef O_CLOEXEC
  fcntl (h->fd, F_SETFD, FD_CLOEXEC);
#endif

  struct stat statbuf;
  if (fstat (h->fd, &statbuf) == -1)
    goto error;

  h->size = statbuf.st_size;

  if (!h->writable) {
    h->addr = mmap (NULL, h->size, PROT_READ, MAP_SHARED, h->fd, 0);
    if (h->addr == MAP_FAILED)
      goto error;

    DEBUG (2, "mapped file at %p", h->addr);
  } else {
    h->addr = malloc (h->size);
    if (h->addr == NULL)
      goto error;

    if (full_read (h->fd, h->addr, h->size) < h->size)
      goto error;

    /* We don't need the file descriptor along this path, since we
     * have read all the data.
     */
    if (close (h->fd) == -1)
      goto error;
    h->fd = -1;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -103,6 +103,13 @@
     goto error;
 
   h->size = statbuf.st_size;
+
+  if (h->size < 0x2000) {
+    SET_ERRNO (EINVAL,
+               "%s: file is too small to be a Windows NT Registry hive file",
+               filename);
+    goto error;
+  }
 
   if (!h->writable) {
     h->addr = mmap (NULL, h->size, PROT_READ, MAP_SHARED, h->fd, 0);
```
