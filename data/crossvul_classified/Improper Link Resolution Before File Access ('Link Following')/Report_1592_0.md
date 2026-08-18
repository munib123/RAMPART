# CrossVul Fix Pair: Improper Link Resolution Before File Access ('Link Following') in c
**Pair ID:** 1592_0
**Vulnerability Class:** Improper Link Resolution Before File Access ('Link Following')
**CWE:** CWE-59
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `1592_0`)

## Vulnerability Information & PoC

## Description
Improper Link Resolution Before File Access ('Link Following') - The product attempts to access a file based on the filename, but it does not properly prevent that filename from identifying a link or shortcut that resolves to an unintended resource.

## Vulnerable Code
```c
Lines 380-420 of the vulnerable file.

     || !S_ISREG(sb.st_mode)
     || sb.st_nlink != 1
    /* kernel internal dumper checks this too: if (inode->i_uid != current->fsuid) <fail>, need to mimic? */
    ) {
        if (user_core_fd < 0)
            perror_msg("Can't open '%s'", full_core_basename);
        else
            perror_msg("'%s' is not a regular file with link count 1", full_core_basename);
        return -1;
    }
    if (ftruncate(user_core_fd, 0) != 0) {
        /* perror first, otherwise unlink may trash errno */
        perror_msg("Can't truncate '%s' to size 0", full_core_basename);
        unlink(core_basename);
        return -1;
    }

    return user_core_fd;
}

static bool dump_fd_info(const char *dest_filename, char *source_filename, int source_base_ofs)
{
    FILE *fp = fopen(dest_filename, "w");
    if (!fp)
        return false;

    unsigned fd = 0;
    while (fd <= 99999) /* paranoia check */
    {
        sprintf(source_filename + source_base_ofs, "fd/%u", fd);
        char *name = malloc_readlink(source_filename);
        if (!name)
            break;
        fprintf(fp, "%u:%s\n", fd, name);
        free(name);

        sprintf(source_filename + source_base_ofs, "fdinfo/%u", fd);
        fd++;
        FILE *in = fopen(source_filename, "r");
        if (!in)
            continue;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -397,7 +397,7 @@
     return user_core_fd;
 }
 
-static bool dump_fd_info(const char *dest_filename, char *source_filename, int source_base_ofs)
+static bool dump_fd_info(const char *dest_filename, char *source_filename, int source_base_ofs, uid_t uid, gid_t gid)
 {
     FILE *fp = fopen(dest_filename, "w");
     if (!fp)
@@ -429,6 +429,16 @@
         }
         fclose(in);
     }
+
+    const int dest_fd = fileno(fp);
+    if (fchown(dest_fd, uid, gid) < 0)
+    {
+        perror_msg("Can't change '%s' ownership to %lu:%lu", dest_filename, (long)uid, (long)gid);
+        fclose(fp);
+        unlink(dest_filename);
+        return false;
+    }
+
     fclose(fp);
     return true;
 }
@@ -678,27 +688,22 @@
 
         // Disabled for now: /proc/PID/smaps tends to be BIG,
         // and not much more informative than /proc/PID/maps:
-        //copy_file(source_filename, dest_filename, 0640);
-        //chown(dest_filename, dd->dd_uid, dd->dd_gid);
+        //copy_file_ext(source_filename, dest_filename, 0640, dd->dd_uid, dd->dd_gid, O_RDONLY, O_WRONLY | O_CREAT | O_TRUNC | O_EXCL);
 
         strcpy(source_filename + source_base_ofs, "maps");
         strcpy(dest_base, FILENAME_MAPS);
-        copy_file(source_filename, dest_filename, DEFAULT_DUMP_DIR_MODE);
-        IGNORE_RESULT(chown(dest_filename, dd->dd_uid, dd->dd_gid));
+        copy_file_ext(source_filename, dest_filename, 0640, dd->dd_uid, dd->dd_gid, O_RDONLY, O_WRONLY | O_CREAT | O_TRUNC | O_EXCL);
 
         strcpy(source_filename + source_base_ofs, "limits");
         strcpy(dest_base, FILENAME_LIMITS);
-        copy_file(source_filename, dest_filename, DEFAULT_DUMP_DIR_MODE);
-        IGNORE_RESULT(chown(dest_filename, dd->dd_uid, dd->dd_gid));
+        copy_file_ext(source_filename, dest_filename, 0640, dd->dd_uid, dd->dd_gid, O_RDONLY, O_WRONLY | O_CREAT | O_TRUNC | O_EXCL);
 
         strcpy(source_filename + source_base_ofs, "cgroup");
         strcpy(dest_base, FILENAME_CGROUP);
-        copy_file(source_filename, dest_filename, DEFAULT_DUMP_DIR_MODE);
-        IGNORE_RESULT(chown(dest_filename, dd->dd_uid, dd->dd_gid));
+        copy_file_ext(source_filename, dest_filename, 0640, dd->dd_uid, dd->dd_gid, O_RDONLY, O_WRONLY | O_CREAT | O_TRUNC | O_EXCL);
 
         strcpy(dest_base, FILENAME_OPEN_FDS);
-        if (dump_fd_info(dest_filename, source_filename, source_base_ofs))
-            IGNORE_RESULT(chown(dest_filename, dd->dd_uid, dd->dd_gid));
+        dump_fd_info(dest_filename, source_filename, source_base_ofs, dd->dd_uid, dd->dd_gid);
 
         free(dest_filename);
 
```
