# CrossVul Fix Pair: Improper Restriction of Operations within the Bounds of a Memory Buffer in c
**Pair ID:** 901_0
**Vulnerability Class:** Memory Corruption - Generic
**CWE:** CWE-119
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `901_0`)

## Vulnerability Information & PoC

## Description
Improper Restriction of Operations within the Bounds of a Memory Buffer - Certain languages allow direct addressing of memory locations and do not automatically ensure that these locations are valid for the memory buffer that is being referenced.

## Vulnerable Code
```c
Lines 3185-3225 of the vulnerable file.

	for(i=0;i<nparam->p.Integer;i++) 
	{
		puts(getName(pop()));
	}
	println(" ;");
	return 0;
}

static int
decompileCAST(int n, SWF_ACTION *actions, int maxn)
{
	struct SWF_ACTIONPUSHPARAM *iparam=pop();
	struct SWF_ACTIONPUSHPARAM *tparam=pop();
	push(newVar_N( getName(tparam),"(",getName(iparam),"", 0,")")); 
	return 0;
}

int
decompileAction(int n, SWF_ACTION *actions, int maxn)
{
	if( n > maxn ) SWF_error("Action overflow!!");

#ifdef DEBUG
	fprintf(stderr,"%d:\tACTION[%3.3d]: %s\n",
	        actions[n].SWF_ACTIONRECORD.Offset, n, 
	        actionName(actions[n].SWF_ACTIONRECORD.ActionCode));
#endif

	switch(actions[n].SWF_ACTIONRECORD.ActionCode)
	{
	case SWFACTION_END:
		return 0;

	case SWFACTION_CONSTANTPOOL:
		decompileCONSTANTPOOL(&actions[n]);
		return 0;

	case SWFACTION_GOTOLABEL:
		return decompileGOTOFRAME(n, actions, maxn,1);

	case SWFACTION_GOTOFRAME:
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -3202,7 +3202,6 @@
 int
 decompileAction(int n, SWF_ACTION *actions, int maxn)
 {
-	if( n > maxn ) SWF_error("Action overflow!!");
 
 #ifdef DEBUG
 	fprintf(stderr,"%d:\tACTION[%3.3d]: %s\n",
@@ -3210,7 +3209,7 @@
 	        actionName(actions[n].SWF_ACTIONRECORD.ActionCode));
 #endif
 
-	switch(actions[n].SWF_ACTIONRECORD.ActionCode)
+	switch(OpCode(actions, n, maxn))
 	{
 	case SWFACTION_END:
 		return 0;
```
