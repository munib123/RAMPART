# CrossVul Fix Pair: Permissions, Privileges, and Access Controls in c
**Pair ID:** 3470_2
**Vulnerability Class:** Improper Access Control - Generic
**CWE:** CWE-264
**Language:** c
**Source:** CrossVul dataset (`hitoshura25/crossvul`, file pair `3470_2`)

## Vulnerability Information & PoC

## Description
Permissions, Privileges, and Access Controls

## Vulnerable Code
```c
Lines 230-270 of the vulnerable file.

const char *string_of_NPPVariable(int variable)
{
  const char *str;

  switch (variable) {
#define _(VAL) case VAL: str = #VAL; break;
	_(NPPVpluginNameString);
	_(NPPVpluginDescriptionString);
	_(NPPVpluginWindowBool);
	_(NPPVpluginTransparentBool);
	_(NPPVjavaClass);
	_(NPPVpluginWindowSize);
	_(NPPVpluginTimerInterval);
	_(NPPVpluginScriptableInstance);
	_(NPPVpluginScriptableIID);
	_(NPPVjavascriptPushCallerBool);
	_(NPPVpluginKeepLibraryInMemory);
	_(NPPVpluginNeedsXEmbed);
	_(NPPVpluginScriptableNPObject);
	_(NPPVformValue);
#undef _
  default:
	switch (variable & 0xff) {
#define _(VAL, VAR) case VAL: str = #VAR; break
	  _(10, NPPVpluginScriptableInstance);
#undef _
	default:
	  str = "<unknown variable>";
	  break;
	}
	break;
  }

  return str;
}

const char *string_of_NPNVariable(int variable)
{
  const char *str;

  switch (variable) {
```

## Fix (vulnerable -> fixed)
```diff
--- vulnerable
+++ fixed
@@ -247,6 +247,11 @@
 	_(NPPVpluginNeedsXEmbed);
 	_(NPPVpluginScriptableNPObject);
 	_(NPPVformValue);
+	_(NPPVpluginUrlRequestsDisplayedBool);
+	_(NPPVpluginWantsAllNetworkStreams);
+	_(NPPVpluginNativeAccessibleAtkPlugId);
+	_(NPPVpluginCancelSrcStream);
+	_(NPPVSupportsAdvancedKeyHandling);
 #undef _
   default:
 	switch (variable & 0xff) {
@@ -283,6 +288,8 @@
 	_(NPNVWindowNPObject);
 	_(NPNVPluginElementNPObject);
 	_(NPNVSupportsWindowless);
+	_(NPNVprivateModeBool);
+	_(NPNVsupportsAdvancedKeyHandling);
 #undef _
   default:
 	switch (variable & 0xff) {
```
