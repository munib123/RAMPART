# CrossVul Fix Pair: Improper Input Validation in c
**Pair ID:** 5533_0
**Vulnerability Class:** Improper Input Validation
**CWE:** CWE-20
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `5533_0`)

## Vulnerability Information & PoC

## Description
Improper Input Validation - Input validation is a frequently-used technique for checking potentially dangerous inputs in order to ensure that the inputs are safe for processing within the code, or when communicating with othe...

## Vulnerable Code
```c
Lines 1-40 of the vulnerable file.

/* diskstore.c implements a very simple disk backed key-value store used
 * by Redis for the "disk" backend. This implementation uses the filesystem
 * to store key/value pairs. Every file represents a given key.
 *
 * The key path is calculated using the SHA1 of the key name. For instance
 * the key "foo" is stored as a file name called:
 *
 *  /0b/ee/0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33
 *
 * The couples of characters from the hex output of SHA1 are also used
 * to locate two two levels of directories to store the file (as most
 * filesystems are not able to handle too many files in a single dir).
 *
 * In the end there are 65536 final directories (256 directories inside
 * every 256 top level directories), so that with 1 billion of files every
 * directory will contain in the average 15258 entires, that is ok with
 * most filesystems implementation.
 *
 * The actaul implementation of this disk store is highly related to the
 * filesystem implementation. This implementation may be replaced by
 * a B+TREE implementation in future implementations.
 *
 * Data ok every key is serialized using the same format used for .rdb
 * serialization. Everything is serialized on every entry: key name,
 * ttl information in case of keys with an associated expire time, and the
 * serialized value itself.
 *
 * Because the format is the same of the .rdb files it is trivial to create
 * an .rdb file starting from this format just by mean of scanning the
 * directories and concatenating entries, with the sole addition of an
 * .rdb header at the start and the end-of-db opcode at the end.
 *
 * -------------------------------------------------------------------------
 *
 * Copyright (c) 2010-2011, Salvatore Sanfilippo <antirez at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -16,8 +16,17 @@
  * directory will contain in the average 15258 entires, that is ok with
  * most filesystems implementation.
  *
- * The actaul implementation of this disk store is highly related to the
- * filesystem implementation. This implementation may be replaced by
+ * Note that since Redis supports multiple databases, the actual key name
+ * is:
+ *
+ *  /0b/ee/<dbid>_0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33
+ *
+ *  so for instance if the key is inside DB 0:
+ *
+ *  /0b/ee/0_0beec7b5ea3f0fdbc95d0dd47f3c5bc275da8a33
+ *
+ * The actaul implementation of this disk store is highly dependant to the
+ * filesystem implementation itself. This implementation may be replaced by
  * a B+TREE implementation in future implementations.
  *
  * Data ok every key is serialized using the same format used for .rdb
@@ -68,7 +77,7 @@
 int dsOpen(void) {
     struct stat sb;
     int retval;
-    char *path = server.diskstore_path;
+    char *path = server.ds_path;
 
     if ((retval = stat(path,&sb) == -1) && errno != ENOENT) {
         redisLog(REDIS_WARNING, "Error opening disk store at %s: %s",
```
