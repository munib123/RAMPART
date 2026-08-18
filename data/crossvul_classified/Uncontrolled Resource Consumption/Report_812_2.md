# CrossVul Fix Pair: Uncontrolled Resource Consumption in c
**Pair ID:** 812_2
**Vulnerability Class:** Uncontrolled Resource Consumption
**CWE:** CWE-400
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `812_2`)

## Vulnerability Information & PoC

## Description
Uncontrolled Resource Consumption - Limited resources include memory, file system storage, database connection pool entries, and CPU.

## Vulnerable Code
```c
Lines 1-39 of the vulnerable file.

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <setjmp.h>
#include <limits.h>

#include "regexp.h"
#include "utf.h"

#define emit regemit
#define next regnext
#define accept regaccept

#define nelem(a) (int)(sizeof (a) / sizeof (a)[0])

#define REPINF 255
#define MAXSUB REG_MAXSUB
#define MAXPROG (32 << 10)

typedef struct Reclass Reclass;
typedef struct Renode Renode;
typedef struct Reinst Reinst;
typedef struct Rethread Rethread;

struct Reclass {
	Rune *end;
	Rune spans[64];
};

struct Reprog {
	Reinst *start, *end;
	int flags;
	int nsub;
	Reclass cclass[16];
};

struct cstate {
	Reprog *prog;
	Renode *pstart, *pend;
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -16,6 +16,7 @@
 #define REPINF 255
 #define MAXSUB REG_MAXSUB
 #define MAXPROG (32 << 10)
+#define MAXREC 1024
 
 typedef struct Reclass Reclass;
 typedef struct Renode Renode;
@@ -967,87 +968,101 @@
 	return 0;
 }
 
-static int match(Reinst *pc, const char *sp, const char *bol, int flags, Resub *out)
+static int match(Reinst *pc, const char *sp, const char *bol, int flags, Resub *out, int depth)
 {
 	Resub scratch;
+	int result;
 	int i;
 	Rune c;
+
+	/* stack overflow */
+	if (depth > MAXREC)
+		return -1;
 
 	for (;;) {
 		switch (pc->opcode) {
 		case I_END:
-			return 1;
+			return 0;
 		case I_JUMP:
 			pc = pc->x;
 			break;
 		case I_SPLIT:
 			scratch = *out;
-			if (match(pc->x, sp, bol, flags, &scratch)) {
+			result = match(pc->x, sp, bol, flags, &scratch, depth+1);
+			if (result == -1)
+				return -1;
+			if (result == 0) {
 				*out = scratch;
-				return 1;
+				return 0;
 			}
 			pc = pc->y;
 			break;
 
 		case I_PLA:
-			if (!match(pc->x, sp, bol, flags, out))
-				return 0;
+			result = match(pc->x, sp, bol, flags, out, depth+1);
+			if (result == -1)
+				return -1;
+			if (result == 1)
+				return 1;
 			pc = pc->y;
 			break;
 		case I_NLA:
 			scratch = *out;
-			if (match(pc->x, sp, bol, flags, &scratch))
-				return 0;
+			result = match(pc->x, sp, bol, flags, &scratch, depth+1);
+			if (result == -1)
+				return -1;
+			if (result == 0)
+				return 1;
 			pc = pc->y;
 			break;
 
 		case I_ANYNL:
 			sp += chartorune(&c, sp);
 			if (c == 0)
-				return 0;
+				return 1;
 			pc = pc + 1;
 			break;
 		case I_ANY:
 			sp += chartorune(&c, sp);
 			if (c == 0)
-				return 0;
+				return 1;
 			if (isnewline(c))
-				return 0;
+				return 1;
 			pc = pc + 1;
 			break;
 		case I_CHAR:
 			sp += chartorune(&c, sp);
 			if (c == 0)
-				return 0;
+				return 1;
 			if (flags & REG_ICASE)
 				c = canon(c);
 			if (c != pc->c)
-				return 0;
+				return 1;
 			pc = pc + 1;
 			break;
 		case I_CCLASS:
 			sp += chartorune(&c, sp);
 			if (c == 0)
-				return 0;
+				return 1;
 			if (flags & REG_ICASE) {
 				if (!incclasscanon(pc->cc, canon(c)))
-					return 0;
+					return 1;
 			} else {
 				if (!incclass(pc->cc, c))
-					return 0;
+					return 1;
 			}
 			pc = pc + 1;
 			break;
 		case I_NCCLASS:
 			sp += chartorune(&c, sp);
 			if (c == 0)
-				return 0;
+				return 1;
 			if (flags & REG_ICASE) {
 				if (incclasscanon(pc->cc, canon(c)))
-					return 0;
+					return 1;
 			} else {
 				if (incclass(pc->cc, c))
-					return 0;
+					return 1;
 			}
 			pc = pc + 1;
 			break;
@@ -1055,10 +1070,10 @@
 			i = out->sub[pc->n].ep - out->sub[pc->n].sp;
 			if (flags & REG_ICASE) {
 				if (strncmpcanon(sp, out->sub[pc->n].sp, i))
-					return 0;
+					return 1;
 			} else {
 				if (strncmp(sp, out->sub[pc->n].sp, i))
-					return 0;
+					return 1;
 			}
 			if (i > 0)
 				sp += i;
@@ -1076,7 +1091,7 @@
 					break;
 				}
 			}
-			return 0;
+			return 1;
 		case I_EOL:
 			if (*sp == 0) {
 				pc = pc + 1;
@@ -1088,19 +1103,19 @@
 					break;
 				}
 			}
-			return 0;
+			return 1;
 		case I_WORD:
 			i = sp > bol && iswordchar(sp[-1]);
 			i ^= iswordchar(sp[0]);
 			if (!i)
-				return 0;
+				return 1;
 			pc = pc + 1;
 			break;
 		case I_NWORD:
 			i = sp > bol && iswordchar(sp[-1]);
 			i ^= iswordchar(sp[0]);
 			if (i)
-				return 0;
+				return 1;
 			pc = pc + 1;
 			break;
 
@@ -1113,7 +1128,7 @@
 			pc = pc + 1;
 			break;
 		default:
-			return 0;
+			return 1;
 		}
 	}
 }
@@ -1130,7 +1145,7 @@
 	for (i = 0; i < MAXSUB; ++i)
 		sub->sub[i].sp = sub->sub[i].ep = NULL;
 
-	return !match(prog->start, sp, sp, prog->flags | eflags, sub);
+	return match(prog->start, sp, sp, prog->flags | eflags, sub, 0);
 }
 
 #ifdef TEST
```
