# CrossVul Fix Pair: Release of Invalid Pointer or Reference in c
**Pair ID:** 4273_0
**Vulnerability Class:** Release of Invalid Pointer or Reference
**CWE:** CWE-763
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `4273_0`)

## Vulnerability Information & PoC

## Description
Release of Invalid Pointer or Reference - This weakness can take several forms, such as: The memory was allocated, explicitly or implicitly, via one memory management method and deallocated using a different, non-compatible function (CWE-7...

## Vulnerable Code
```c
Lines 164-211 of the vulnerable file.



/*
** tells whether a key or value can be cleared from a weak
** table. Non-collectable objects are never removed from weak
** tables. Strings behave as 'values', so are never removed too. for
** other objects: if really collected, cannot keep them; for objects
** being finalized, keep them in keys, but not in values
*/
static int iscleared (global_State *g, const GCObject *o) {
  if (o == NULL) return 0;  /* non-collectable value */
  else if (novariant(o->tt) == LUA_TSTRING) {
    markobject(g, o);  /* strings are 'values', so are never weak */
    return 0;
  }
  else return iswhite(o);
}


/*
** barrier that moves collector forward, that is, mark the white object
** 'v' being pointed by the black object 'o'. (If in sweep phase, clear
** the black object to white [sweep it] to avoid other barrier calls for
** this same object.) In the generational mode, 'v' must also become
** old, if 'o' is old; however, it cannot be changed directly to OLD,
** because it may still point to non-old objects. So, it is marked as
** OLD0. In the next cycle it will become OLD1, and in the next it
** will finally become OLD (regular old).
*/
void luaC_barrier_ (lua_State *L, GCObject *o, GCObject *v) {
  global_State *g = G(L);
  lua_assert(isblack(o) && iswhite(v) && !isdead(g, v) && !isdead(g, o));
  if (keepinvariant(g)) {  /* must keep invariant? */
    reallymarkobject(g, v);  /* restore invariant */
    if (isold(o)) {
      lua_assert(!isold(v));  /* white object could not be old */
      setage(v, G_OLD0);  /* restore generational invariant */
    }
  }
  else {  /* sweep phase */
    lua_assert(issweepphase(g));
    makewhite(g, o);  /* mark main obj. as white to avoid other barriers */
  }
}


/*
** barrier that moves collector backward, that is, mark the black object
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -181,14 +181,17 @@
 
 
 /*
-** barrier that moves collector forward, that is, mark the white object
-** 'v' being pointed by the black object 'o'. (If in sweep phase, clear
-** the black object to white [sweep it] to avoid other barrier calls for
-** this same object.) In the generational mode, 'v' must also become
-** old, if 'o' is old; however, it cannot be changed directly to OLD,
-** because it may still point to non-old objects. So, it is marked as
-** OLD0. In the next cycle it will become OLD1, and in the next it
-** will finally become OLD (regular old).
+** Barrier that moves collector forward, that is, marks the white object
+** 'v' being pointed by the black object 'o'.  In the generational
+** mode, 'v' must also become old, if 'o' is old; however, it cannot
+** be changed directly to OLD, because it may still point to non-old
+** objects. So, it is marked as OLD0. In the next cycle it will become
+** OLD1, and in the next it will finally become OLD (regular old). By
+** then, any object it points to will also be old.  If called in the
+** incremental sweep phase, it clears the black object to white (sweep
+** it) to avoid other barrier calls for this same object. (That cannot
+** be done is generational mode, as its sweep does not distinguish
+** whites from deads.)
 */
 void luaC_barrier_ (lua_State *L, GCObject *o, GCObject *v) {
   global_State *g = G(L);
@@ -202,7 +205,8 @@
   }
   else {  /* sweep phase */
     lua_assert(issweepphase(g));
-    makewhite(g, o);  /* mark main obj. as white to avoid other barriers */
+    if (g->gckind == KGC_INC)  /* incremental mode? */
+      makewhite(g, o);  /* mark 'o' as white to avoid other barriers */
   }
 }
 
@@ -324,10 +328,15 @@
 
 
 /*
-** Mark all values stored in marked open upvalues from non-marked threads.
-** (Values from marked threads were already marked when traversing the
-** thread.) Remove from the list threads that no longer have upvalues and
-** not-marked threads.
+** For each non-marked thread, simulates a barrier between each open
+** upvalue and its value. (If the thread is collected, the value will be
+** assigned to the upvalue, but then it can be too late for the barrier
+** to act. The "barrier" does not need to check colors: A non-marked
+** thread must be young; upvalues cannot be older than their threads; so
+** any visited upvalue must be young too.) Also removes the thread from
+** the list, as it was already visited. Removes also threads with no
+** upvalues, as they have nothing to be checked. (If the thread gets an
+** upvalue later, it will be linked in the list again.)
 */
 static int remarkupvals (global_State *g) {
   lua_State *thread;
@@ -340,9 +349,11 @@
       p = &thread->twups;  /* keep marked thread with upvalues in the list */
     else {  /* thread is not marked or without upvalues */
       UpVal *uv;
+      lua_assert(!isold(thread) || thread->openupval == NULL);
       *p = thread->twups;  /* remove thread from the list */
       thread->twups = thread;  /* mark that it is out of list */
       for (uv = thread->openupval; uv != NULL; uv = uv->u.open.next) {
+        lua_assert(getage(uv) <= getage(thread));
         work++;
         if (!iswhite(uv))  /* upvalue already visited? */
           markvalue(g, uv->v);  /* mark its value */
@@ -995,6 +1006,9 @@
 ** during the sweep. So, any white object must be dead.) For
 ** non-dead objects, advance their ages and clear the color of
 ** new objects. (Old objects keep their colors.)
+** The ages of G_TOUCHED1 and G_TOUCHED2 objects will advance
+** in 'correctgraylist'. (That function will also remove objects
+** turned white here from any gray list.)
 */
 static GCObject **sweepgen (lua_State *L, global_State *g, GCObject **p,
                             GCObject *limit) {
@@ -1055,16 +1069,16 @@
           lua_assert(isgray(curr));
           gray2black(curr);  /* make it black, for next barrier */
           changeage(curr, G_TOUCHED1, G_TOUCHED2);
-          p = next;  /* go to next element */
+          p = next;  /* keep it in the list and go to next element */
         }
-        else {  /* not touched in this cycle */
+        else {  /* everything else is removed */
+          /* white objects are simply removed */
           if (!iswhite(curr)) {  /* not white? */
             lua_assert(isold(curr));
             if (getage(curr) == G_TOUCHED2)  /* advance from G_TOUCHED2... */
               changeage(curr, G_TOUCHED2, G_OLD);  /* ... to G_OLD */
             gray2black(curr);  /* make it black */
           }
-          /* else, object is white: just remove it from this list */
           *p = *next;  /* remove 'curr' from gray list */
         }
         break;
@@ -1143,6 +1157,7 @@
   atomic(L);
 
   /* sweep nursery and get a pointer to its last live element */
+  g->gcstate = GCSswpallgc;
   psurvival = sweepgen(L, g, &g->allgc, g->survival);
   /* sweep 'survival' and 'old' */
   sweepgen(L, g, psurvival, g->reallyold);
@@ -1166,6 +1181,7 @@
 
 static void atomic2gen (lua_State *L, global_State *g) {
   /* sweep all elements making them old */
+  g->gcstate = GCSswpallgc;
   sweep2old(L, &g->allgc);
   /* everything alive now is old */
   g->reallyold = g->old = g->survival = g->allgc;
```
