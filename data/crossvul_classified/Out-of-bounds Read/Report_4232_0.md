# CrossVul Fix Pair: Out-of-bounds Read in c
**Pair ID:** 4232_0
**Vulnerability Class:** Out-of-bounds Read
**CWE:** CWE-125
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4232_0`)

## Vulnerability Information & PoC

## Description
Out-of-bounds Read - Typically, this can allow attackers to read sensitive information from other memory locations or cause a crash.

## Vulnerable Code
```c
Lines 1114-1158 of the vulnerable file.

        reallymarkobject(g, p);
      }
    }
  }
}


/*
** Finish a young-generation collection.
*/
static void finishgencycle (lua_State *L, global_State *g) {
  correctgraylists(g);
  checkSizes(L, g);
  g->gcstate = GCSpropagate;  /* skip restart */
  if (!g->gcemergency)
    callallpendingfinalizers(L);
}


/*
** Does a young collection. First, mark 'OLD1' objects.  (Only survival
** and "recent old" lists can contain 'OLD1' objects. New lists cannot
** contain 'OLD1' objects, at most 'OLD0' objects that were already
** visited when marked old.) Then does the atomic step. Then,
** sweep all lists and advance pointers. Finally, finish the collection.
*/
static void youngcollection (lua_State *L, global_State *g) {
  GCObject **psurvival;  /* to point to first non-dead survival object */
  lua_assert(g->gcstate == GCSpropagate);
  markold(g, g->survival, g->reallyold);
  markold(g, g->finobj, g->finobjrold);
  atomic(L);

  /* sweep nursery and get a pointer to its last live element */
  psurvival = sweepgen(L, g, &g->allgc, g->survival);
  /* sweep 'survival' and 'old' */
  sweepgen(L, g, psurvival, g->reallyold);
  g->reallyold = g->old;
  g->old = *psurvival;  /* 'survival' survivals are old now */
  g->survival = g->allgc;  /* all news are survivals */

  /* repeat for 'finobj' lists */
  psurvival = sweepgen(L, g, &g->finobj, g->finobjsur);
  /* sweep 'survival' and 'old' */
  sweepgen(L, g, psurvival, g->finobjrold);
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -1131,16 +1131,14 @@
 
 
 /*
-** Does a young collection. First, mark 'OLD1' objects.  (Only survival
-** and "recent old" lists can contain 'OLD1' objects. New lists cannot
-** contain 'OLD1' objects, at most 'OLD0' objects that were already
-** visited when marked old.) Then does the atomic step. Then,
-** sweep all lists and advance pointers. Finally, finish the collection.
+** Does a young collection. First, mark 'OLD1' objects. Then does the
+** atomic step. Then, sweep all lists and advance pointers. Finally,
+** finish the collection.
 */
 static void youngcollection (lua_State *L, global_State *g) {
   GCObject **psurvival;  /* to point to first non-dead survival object */
   lua_assert(g->gcstate == GCSpropagate);
-  markold(g, g->survival, g->reallyold);
+  markold(g, g->allgc, g->reallyold);
   markold(g, g->finobj, g->finobjrold);
   atomic(L);
 
```
