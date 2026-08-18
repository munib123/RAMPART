# CrossVul Fix Pair: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') in c
**Pair ID:** 4523_1
**Vulnerability Class:** Classic Buffer Overflow
**CWE:** CWE-120
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4523_1`)

## Vulnerability Information & PoC

## Description
Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') - A buffer overflow condition exists when a product attempts to put more data in a buffer than it can hold, or when it attempts to put data in a memory area outside of the boundaries of a buffer.

## Vulnerable Code
```c
Lines 983-1023 of the vulnerable file.

            if ((players[i][1] == 'p'
                 && str2role(arg) == str2role(t1->plrole))
                || (players[i][1] == 'r'
                    && str2race(arg) == str2race(t1->plrace)))
                return 1;
            i++;
        } else if (strcmp(players[i], "all") == 0
                   || strncmp(t1->name, players[i], NAMSZ) == 0
                   || (players[i][0] == '-' && players[i][1] == t1->plrole[0]
                       && players[i][2] == 0)
                   || (digit(players[i][0]) && rank <= atoi(players[i])))
            return 1;
    }
    return 0;
}

/*
 * print selected parts of score list.
 * argc >= 2, with argv[0] untrustworthy (directory names, et al.),
 * and argv[1] starting with "-s".
 */
void
prscore(argc, argv)
int argc;
char **argv;
{
    const char **players;
    int playerct, rank;
    boolean current_ver = TRUE, init_done = FALSE;
    register struct toptenentry *t1;
    FILE *rfile;
    boolean match_found = FALSE;
    register int i;
    char pbuf[BUFSZ];
    int uid = -1;
    const char *player0;

    if (argc < 2 || strncmp(argv[1], "-s", 2)) {
        raw_printf("prscore: bad arguments (%d)", argc);
        return;
    }
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1000,6 +1000,7 @@
  * print selected parts of score list.
  * argc >= 2, with argv[0] untrustworthy (directory names, et al.),
  * and argv[1] starting with "-s".
+ * caveat: some shells might allow argv elements to be arbitrarily long.
  */
 void
 prscore(argc, argv)
```
