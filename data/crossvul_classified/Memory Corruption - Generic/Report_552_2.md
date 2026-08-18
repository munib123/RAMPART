# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 552_2
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `552_2`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 366-398 of the vulnerable file.

        return -1;
    } else if (argc > 3) {
        send_error(5);
        return -1;
    }

    build_needs_escape();

    if (argv[2] == NULL)
        index_directory(argv[1], argv[1]);
    else
        index_directory(argv[1], argv[2]);

    time(&timep);
#ifdef USE_LOCALTIME
    timeptr = localtime(&timep);
#else
    timeptr = gmtime(&timep);
#endif
    now = strdup(asctime(timeptr));
    now[strlen(now) - 1] = '\0';
#ifdef USE_LOCALTIME
    printf("</table>\n<hr noshade>\nIndex generated %s %s\n"
           "<!-- This program is part of the Boa Webserver Copyright (C) 1991-2002 http://www.boa.org -->\n"
           "</body>\n</html>\n", now, TIMEZONE(timeptr));
#else
    printf("</table>\n<hr noshade>\nIndex generated %s UTC\n"
           "<!-- This program is part of the Boa Webserver Copyright (C) 1991-2002 http://www.boa.org -->\n"
           "</body>\n</html>\n", now);
#endif

    return 0;
}
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -383,6 +383,9 @@
     timeptr = gmtime(&timep);
 #endif
     now = strdup(asctime(timeptr));
+	if (!now) {
+		return -1;
+	}
     now[strlen(now) - 1] = '\0';
 #ifdef USE_LOCALTIME
     printf("</table>\n<hr noshade>\nIndex generated %s %s\n"
@@ -393,6 +396,6 @@
            "<!-- This program is part of the Boa Webserver Copyright (C) 1991-2002 http://www.boa.org -->\n"
            "</body>\n</html>\n", now);
 #endif
-
+	free(now);
     return 0;
 }
```
