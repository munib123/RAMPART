# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 552_4
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `552_4`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 125-147 of the vulnerable file.

        return 1;
    }
    fd = open_gen_fd(argv[1]);
    if (fd < 0) {
        perror("open_gen_fd");
        exit(EXIT_FAILURE);
    }
    while ((nr = read(0, buff, sizeof (buff))) != 0) {
        if (nr < 0) {
            if (errno == EINTR)
                continue;
            perror("read");
            exit(EXIT_FAILURE);
        }
        nw = write(fd, buff, nr);
        if (nw < 0) {
            perror("write");
            exit(EXIT_FAILURE);
        }
    }
    return 0;
}
#endif
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -142,6 +142,7 @@
             exit(EXIT_FAILURE);
         }
     }
+	close(fd);
     return 0;
 }
 #endif
```
