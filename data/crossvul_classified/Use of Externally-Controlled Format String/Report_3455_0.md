# CrossVul Fix Pair: Use of Externally-Controlled Format String in c
**Pair ID:** 3455_0
**Vulnerability Class:** Use of Externally-Controlled Format String
**CWE:** CWE-134
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3455_0`)

## Vulnerability Information & PoC

## Description
Use of Externally-Controlled Format String - When an attacker can modify an externally-controlled format string, this can lead to buffer overflows, denial of service, or data representation problems.

## Vulnerable Code
```c
Lines 517-557 of the vulnerable file.

          g_free (base_name);
        }
      else
        target_file = g_object_ref (target_file);

      /* query file info */
      info = g_file_query_info (node->source_file,
                                G_FILE_ATTRIBUTE_STANDARD_DISPLAY_NAME,
                                G_FILE_QUERY_INFO_NOFOLLOW_SYMLINKS,
                                exo_job_get_cancellable (EXO_JOB (job)),
                                &err);

      /* abort on error or cancellation */
      if (info == NULL)
        {
          g_object_unref (target_file);
          break;
        }

      /* update progress information */
      exo_job_info_message (EXO_JOB (job), g_file_info_get_display_name (info));

retry_copy:
      /* copy the item specified by this node (not recursively) */
      real_target_file = thunar_transfer_job_copy_file (job, node->source_file, 
                                                        target_file, &err);
      if (G_LIKELY (real_target_file != NULL))
        {
          /* node->source_file == real_target_file means to skip the file */
          if (G_LIKELY (node->source_file != real_target_file))
            {
              /* notify the thumbnail cache of the copy operation */
              thunar_thumbnail_cache_copy_file (thumbnail_cache, 
                                                node->source_file, 
                                                real_target_file);

              /* check if we have children to copy */
              if (node->children != NULL)
                {
                  /* copy all children of this node */
                  thunar_transfer_job_copy_node (job, node->children, NULL, real_target_file, NULL, &err);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -534,7 +534,7 @@
         }
 
       /* update progress information */
-      exo_job_info_message (EXO_JOB (job), g_file_info_get_display_name (info));
+      exo_job_info_message (EXO_JOB (job), "%s", g_file_info_get_display_name (info));
 
 retry_copy:
       /* copy the item specified by this node (not recursively) */
```
