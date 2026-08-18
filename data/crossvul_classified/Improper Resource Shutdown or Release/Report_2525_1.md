# CrossVul Fix Pair: Improper Resource Shutdown or Release in c
**Pair ID:** 2525_1
**Vulnerability Class:** Improper Resource Shutdown or Release
**CWE:** CWE-404
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `2525_1`)

## Vulnerability Information & PoC

## Description
Improper Resource Shutdown or Release - When a resource is created or allocated, the developer is responsible for properly releasing the resource as well as accounting for all potential paths of expiration or invalidation, such as a set ...

## Vulnerable Code
```c
Lines 3089-3129 of the vulnerable file.


      /* -oMm: Message reference */

      else if (Ustrcmp(argrest, "Mm") == 0)
        {
        if (!mac_ismsgid(argv[i+1]))
          {
            fprintf(stderr,"-oMm must be a valid message ID\n");
            exit(EXIT_FAILURE);
          }
        if (!trusted_config)
          {
            fprintf(stderr,"-oMm must be called by a trusted user/config\n");
            exit(EXIT_FAILURE);
          }
          message_reference = argv[++i];
        }

      /* -oMr: Received protocol */

      else if (Ustrcmp(argrest, "Mr") == 0) received_protocol = argv[++i];

      /* -oMs: Set sender host name */

      else if (Ustrcmp(argrest, "Ms") == 0) sender_host_name = argv[++i];

      /* -oMt: Set sender ident */

      else if (Ustrcmp(argrest, "Mt") == 0)
        {
        sender_ident_set = TRUE;
        sender_ident = argv[++i];
        }

      /* Else a bad argument */

      else
        {
        badarg = TRUE;
        break;
        }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3106,7 +3106,14 @@
 
       /* -oMr: Received protocol */
 
-      else if (Ustrcmp(argrest, "Mr") == 0) received_protocol = argv[++i];
+      else if (Ustrcmp(argrest, "Mr") == 0)
+
+        if (received_protocol)
+          {
+          fprintf(stderr, "received_protocol is set already\n");
+          exit(EXIT_FAILURE);
+          }
+        else received_protocol = argv[++i];
 
       /* -oMs: Set sender host name */
 
@@ -3202,7 +3209,15 @@
 
     if (*argrest != 0)
       {
-      uschar *hn = Ustrchr(argrest, ':');
+      uschar *hn;
+
+      if (received_protocol)
+        {
+        fprintf(stderr, "received_protocol is set already\n");
+        exit(EXIT_FAILURE);
+        }
+
+      hn = Ustrchr(argrest, ':');
       if (hn == NULL)
         {
         received_protocol = argrest;
```
