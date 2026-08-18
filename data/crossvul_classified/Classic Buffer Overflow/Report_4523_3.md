# CrossVul Fix Pair: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') in c
**Pair ID:** 4523_3
**Vulnerability Class:** Classic Buffer Overflow
**CWE:** CWE-120
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4523_3`)

## Vulnerability Information & PoC

## Description
Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') - A buffer overflow condition exists when a product attempts to put more data in a buffer than it can hold, or when it attempts to put data in a memory area outside of the boundaries of a buffer.

## Vulnerable Code
```c
Lines 338-378 of the vulnerable file.

                   and create another for the new character name */
                if (!locknum) {
                    delete_levelfile(0); /* remove empty lock file */
                    getlock();
                }
                goto attempt_restore;
            }
        }
        newgame();
        wd_message();
    }

    /* moveloop() never returns but isn't flagged NORETURN */
    moveloop(resuming);

    exit(EXIT_SUCCESS);
    /*NOTREACHED*/
    return 0;
}

static void
process_options(argc, argv)
int argc;
char *argv[];
{
    int i, l;

    /*
     * Process options.
     */
    while (argc > 1 && argv[1][0] == '-') {
        argv++;
        argc--;
        l = (int) strlen(*argv);
        /* must supply at least 4 chars to match "-XXXgraphics" */
        if (l < 4)
            l = 4;

        switch (argv[0][1]) {
        case 'D':
        case 'd':
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -355,6 +355,7 @@
     return 0;
 }
 
+/* caveat: argv elements might be arbitrary long */
 static void
 process_options(argc, argv)
 int argc;
@@ -383,11 +384,10 @@
                 load_symset("DECGraphics", PRIMARY);
                 switch_symbols(TRUE);
             } else {
-                raw_printf("Unknown option: %s", *argv);
+                raw_printf("Unknown option: %.60s", *argv);
             }
             break;
         case 'X':
-
             discover = TRUE, wizard = FALSE;
             break;
 #ifdef NEWS
@@ -413,7 +413,7 @@
                 load_symset("RogueIBM", ROGUESET);
                 switch_symbols(TRUE);
             } else {
-                raw_printf("Unknown option: %s", *argv);
+                raw_printf("Unknown option: %.60s", *argv);
             }
             break;
         case 'p': /* profession (role) */
@@ -451,7 +451,7 @@
                 flags.initrole = i;
                 break;
             }
-            /* else raw_printf("Unknown option: %s", *argv); */
+            /* else raw_printf("Unknown option: %.60s", *argv); */
         }
     }
 
```
